package settleoutbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// The sweeper is the other half of the outbox (durable-settle-outbox.md
// §9.2): a sibling enclave lists the pending objects, takes a time lease on
// one, and replays its exact bytes to the authority that holds the
// authorization. The pending object is never rewritten; the lease is a
// sibling object under v1/lease/ with the same name, written and released
// with GCS generation preconditions, which is Batch's lease mechanism
// (internal/batch.Service.claim) applied next to an immutable object instead
// of inside a mutable job. The outcome moves the pending object, bytes
// unchanged, to one of the terminal prefixes below; nothing here deletes a
// terminal without a copy of it existing first.
const (
	// DonePrefix holds replayed objects the router settled or had already
	// settled. Kept, not deleted, as Batch keeps its terminal job objects;
	// the bucket's lifecycle rule ages them out.
	DonePrefix = "trustedrouter-settle-outbox/v1/done/"
	// DeadPrefix holds objects the router answered with a deterministic
	// refusal of the authorization itself: 404 (never seen, or past
	// retention) or 409 (a retired settlement kind). A human reads them.
	DeadPrefix = "trustedrouter-settle-outbox/v1/dead/"
	// QuarantinePrefix holds objects that must not be replayed as trusted:
	// unsigned or malformed envelopes, and replays the router refused
	// (401/403). Never deleted by the sweeper.
	QuarantinePrefix = "trustedrouter-settle-outbox/v1/quarantine/"
	leasePrefix      = "trustedrouter-settle-outbox/v1/lease/"

	// DefaultSweepInterval is how often one boot lists a page of pending
	// objects. Modest on purpose: the outbox is recovery, not a hot path.
	DefaultSweepInterval = time.Minute
	// DefaultSweepPageSize bounds one sweep's list and therefore its work.
	DefaultSweepPageSize = 100
	// DefaultLease is how long a claim holds. It exceeds the replay timeout,
	// so a replay that is still running never loses its lease to a sibling.
	DefaultLease = 2 * time.Minute
	// defaultReplayTimeout bounds one replay: a pinned settle retries
	// inside the client's 28 s budget, a refund has its own 10 s deadline.
	defaultReplayTimeout = 45 * time.Second

	// BootAuthRefusedReason is how the router refuses an object's
	// X-TR-Boot-Auth on /settle and /refund (quill-router R3, PR #2048,
	// routes/internal/gateway.py): HTTP 401, error type "unauthorized",
	// message "Gateway boot was not accepted", error.reason this value; the
	// same signal as the heartbeat gate and the disposition lookup. The
	// client surfaces error.reason as ControlPlaneError.Reason. This is
	// the one refusal that is about the object: it quarantines. Until R3 is
	// deployed on the plane the sweeper replays to, QUILL_SETTLE_OUTBOX_SWEEP
	// must stay off: the router would accept any shaped header under the
	// sweeper's own token.
	BootAuthRefusedReason = "boot_not_accepted"

	// senderRefusedMessage is in the router's two refusals of the caller's
	// internal service token (quill-router routes/internal/_shared.py,
	// require_internal_gateway: 401 "Invalid internal service token", 403
	// "Internal service token is required"). They are about this sweeper's
	// credential, not the object, so they stop the sweep instead of filing
	// anything. The label is for the log line; any other 401 or 403 is
	// treated the same way (refusalKindSenderUnknown).
	senderRefusedMessage = "internal service token"
)

// ErrSenderRefused is returned by Sweep when the router refused the
// sweeper's own token: the page stopped, the lease was released, and sweeps
// pause for one lease.
var ErrSenderRefused = errors.New("settleoutbox: router refused the sweeper's internal token")

// Store is the slice of batch.ObjectStore the sweeper uses. *batch.GCSStore
// satisfies it.
type Store interface {
	ObjectStore
	Get(context.Context, string) (batch.StoredObject, error)
	Delete(context.Context, string, int64) error
	List(context.Context, string, int, string) ([]batch.ObjectMeta, string, error)
}

// Replayer posts a frozen terminal. *trustedrouter.Client satisfies it.
type Replayer interface {
	PostFrozenTerminal(context.Context, trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error)
}

// Outcome is what one sweep did with one object.
type Outcome string

const (
	// OutcomeSettled: the router answered 2xx; the object is under done/.
	OutcomeSettled Outcome = "settled"
	// OutcomeDead: the router refused the authorization for good; dead/.
	OutcomeDead Outcome = "dead"
	// OutcomeQuarantined: not replayed as trusted, or refused; quarantine/.
	OutcomeQuarantined Outcome = "quarantined"
	// OutcomeRetry: a 5xx or transport failure; the lease was released with
	// a backoff and the object stays pending.
	OutcomeRetry Outcome = "retry"
	// OutcomeSkipped: another sweeper holds the lease, the object is in its
	// backoff, or it was moved meanwhile.
	OutcomeSkipped Outcome = "skipped"
)

// Report counts one sweep. Listed is the pending objects on the page.
type Report struct {
	Listed, Claimed, Settled, Dead, Quarantined, Retried, Skipped int
	// OrphanLeases counts expired leases dropped because their pending
	// object was gone.
	OrphanLeases int
	// SenderRefused is set when the page stopped on the router refusing
	// the sweeper's token.
	SenderRefused bool
}

// Sweeper replays pending objects. One per boot; Start runs it until ctx
// ends. Sweep is one page, for tests and for the loop.
type Sweeper struct {
	store  Store
	replay Replayer
	logf   func(string, ...any)
	now    func() time.Time
	owner  string

	interval      time.Duration
	pageSize      int
	lease         time.Duration
	replayTimeout time.Duration

	startOnce sync.Once
	mu        sync.Mutex
	// pageToken continues the listing across sweeps so objects in backoff
	// at the front of the prefix do not starve the ones behind them.
	pageToken string
	// pausedUntil is set when the router refused the sweeper's own token;
	// no page is listed before it.
	pausedUntil time.Time
}

// NewSweeper returns a sweeper over store that replays through replay. logf
// may be nil.
func NewSweeper(store Store, replay Replayer, logf func(string, ...any)) *Sweeper {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Sweeper{
		store:         store,
		replay:        replay,
		logf:          logf,
		now:           time.Now,
		owner:         randomOwner(),
		interval:      DefaultSweepInterval,
		pageSize:      DefaultSweepPageSize,
		lease:         DefaultLease,
		replayTimeout: defaultReplayTimeout,
	}
}

// Start sweeps one page every interval until ctx ends. The first sweep waits
// one interval so a boot registers and warms before it replays anything.
func (s *Sweeper) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.startOnce.Do(func() { go s.run(ctx) })
}

func (s *Sweeper) run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		report, err := s.Sweep(ctx)
		if err != nil && !errors.Is(err, ErrSenderRefused) && ctx.Err() == nil {
			s.logf("settle_outbox.sweep_failed owner=%q err=%q", s.owner, err.Error())
		}
		if report.Listed > 0 || report.OrphanLeases > 0 {
			// The counter line the alert reads: a non-zero dead or
			// quarantined count pages (infra/gcp/settle-outbox/main.tf).
			s.logf("settle_outbox.sweep owner=%q pending=%d claimed=%d settled=%d dead=%d quarantined=%d retried=%d skipped=%d orphan_leases=%d",
				s.owner, report.Listed, report.Claimed, report.Settled, report.Dead, report.Quarantined, report.Retried, report.Skipped, report.OrphanLeases)
		}
	}
}

// Sweep lists one page of pending objects and handles each in turn.
func (s *Sweeper) Sweep(ctx context.Context) (Report, error) {
	if s == nil || s.store == nil || s.replay == nil {
		return Report{}, errors.New("settleoutbox: sweeper has no store or replayer")
	}
	now := s.now()
	s.mu.Lock()
	pageToken, paused := s.pageToken, s.pausedUntil
	s.mu.Unlock()
	if now.Before(paused) {
		return Report{}, nil
	}
	objects, nextPageToken, err := s.store.List(ctx, ObjectPrefix, s.pageSize, pageToken)
	if err != nil {
		// Page tokens are opaque and go stale under churn; the next sweep
		// starts from the prefix root (the Batch worker does the same).
		s.setPageToken("")
		return Report{}, err
	}
	s.setPageToken(nextPageToken)
	report := Report{Listed: len(objects)}
	for _, object := range objects {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		result, err := s.sweepObject(ctx, object)
		if result.claimed {
			report.Claimed++
		}
		if err != nil {
			s.logf("settle_outbox.sweep_object_failed owner=%q object=%q err=%q", s.owner, object.Name, err.Error())
		}
		if result.senderRefused {
			// The router refused this sweeper's token, not the object.
			// Every replay on this page would fail the same way and a
			// rotated token must not quarantine the backlog: stop here,
			// the lease is already released, and pause for one lease.
			report.Retried++
			report.SenderRefused = true
			until := s.now().Add(s.lease)
			s.mu.Lock()
			s.pausedUntil = until
			s.mu.Unlock()
			s.logf("settle_outbox.sweep_sender_refused owner=%q object=%q status=%d type=%q paused_until=%q",
				s.owner, object.Name, result.status, result.errorType, until.UTC().Format(time.RFC3339))
			return report, ErrSenderRefused
		}
		switch result.outcome {
		case OutcomeSettled:
			report.Settled++
		case OutcomeDead:
			report.Dead++
		case OutcomeQuarantined:
			report.Quarantined++
		case OutcomeRetry:
			report.Retried++
		default:
			report.Skipped++
		}
	}
	orphans, err := s.sweepLeases(ctx)
	report.OrphanLeases = orphans
	return report, err
}

// sweepLeases drops expired leases whose pending object is gone: a sweeper
// that moved an object and then failed to drop its lease, or died between
// the two, leaves one behind, and the pending listing never visits it.
func (s *Sweeper) sweepLeases(ctx context.Context) (int, error) {
	leases, _, err := s.store.List(ctx, leasePrefix, s.pageSize, "")
	if err != nil {
		return 0, err
	}
	dropped := 0
	now := s.now().UnixMilli()
	for _, meta := range leases {
		if ctx.Err() != nil {
			return dropped, ctx.Err()
		}
		rest := strings.TrimPrefix(meta.Name, leasePrefix)
		stored, err := s.store.Get(ctx, meta.Name)
		if err != nil {
			continue
		}
		var current lease
		if json.Unmarshal(stored.Data, &current) == nil && current.Until > now {
			continue
		}
		if _, err := s.store.Get(ctx, ObjectPrefix+rest); !errors.Is(err, batch.ErrNotFound) {
			continue
		}
		if err := s.store.Delete(ctx, meta.Name, stored.Generation); err != nil && !errors.Is(err, batch.ErrPrecondition) {
			s.logf("settle_outbox.sweep_lease_delete_failed owner=%q lease=%q err=%q", s.owner, meta.Name, err.Error())
			continue
		}
		dropped++
		s.logf("settle_outbox.sweep_orphan_lease_dropped owner=%q lease=%q", s.owner, meta.Name)
	}
	return dropped, nil
}

func (s *Sweeper) setPageToken(token string) {
	s.mu.Lock()
	s.pageToken = token
	s.mu.Unlock()
}

// lease is the sibling object a claim writes. Until is the moment the claim,
// or the backoff after a failed replay, ends; a zero Owner with a future
// Until is a backoff.
type lease struct {
	Owner    string `json:"owner,omitempty"`
	Until    int64  `json:"until_unix_ms"`
	Attempts int    `json:"attempts"`
}

type claim struct {
	name       string
	generation int64
	attempts   int
}

// objectResult is what sweepObject did with one object. claimed reports
// whether this sweeper took the lease; senderRefused that the router refused
// the sweeper's own token (status and errorType say how).
type objectResult struct {
	outcome       Outcome
	claimed       bool
	senderRefused bool
	status        int
	errorType     string
}

// sweepObject claims, replays and files one pending object.
func (s *Sweeper) sweepObject(ctx context.Context, meta batch.ObjectMeta) (objectResult, error) {
	rest := strings.TrimPrefix(meta.Name, ObjectPrefix)
	if rest == "" || !strings.HasPrefix(meta.Name, ObjectPrefix) || strings.HasSuffix(rest, "/") {
		return objectResult{outcome: OutcomeSkipped}, nil
	}
	held, ok, err := s.claim(ctx, rest)
	if err != nil || !ok {
		return objectResult{outcome: OutcomeSkipped}, err
	}
	stored, err := s.store.Get(ctx, meta.Name)
	switch {
	case errors.Is(err, batch.ErrNotFound):
		// Filed by a sibling whose lease outlived ours to see. Nothing to do.
		s.dropLease(ctx, held)
		return objectResult{outcome: OutcomeSkipped, claimed: true}, nil
	case err != nil:
		s.releaseLease(ctx, held)
		return objectResult{outcome: OutcomeRetry, claimed: true}, err
	}
	object, decodeErr := Decode(stored.Data)
	if decodeErr != nil {
		s.logf("settle_outbox.sweep_quarantine owner=%q object=%q reason=%q err=%q", s.owner, meta.Name, "invalid_object", decodeErr.Error())
		return s.file(ctx, meta.Name, stored, held, QuarantinePrefix+rest, OutcomeQuarantined)
	}
	if reason := unverifiedReason(object); reason != "" {
		s.logf("settle_outbox.sweep_quarantine owner=%q object=%q auth_id=%q kind=%q reason=%q kid=%q",
			s.owner, meta.Name, object.AuthorizationID, object.Kind, reason, object.BootKID)
		return s.file(ctx, meta.Name, stored, held, QuarantinePrefix+rest, OutcomeQuarantined)
	}

	replayCtx, cancel := context.WithTimeout(ctx, s.replayTimeout)
	result, replayErr := s.replay.PostFrozenTerminal(replayCtx, object.Terminal())
	cancel()
	verdict := classify(replayErr)
	s.logf("settle_outbox.sweep_replay owner=%q object=%q auth_id=%q kind=%q kid=%q attempt=%d outcome=%q reason=%q status=%d type=%q disposition=%q already_settled=%t",
		s.owner, meta.Name, object.AuthorizationID, object.Kind, object.BootKID, held.attempts,
		verdict.outcome, verdict.reason, verdict.status, verdict.errorType, disposition(result), result != nil && result.AlreadySettled)
	switch verdict.outcome {
	case OutcomeSettled:
		return s.file(ctx, meta.Name, stored, held, DonePrefix+rest, OutcomeSettled)
	case OutcomeDead:
		return s.file(ctx, meta.Name, stored, held, DeadPrefix+rest, OutcomeDead)
	case OutcomeQuarantined:
		return s.file(ctx, meta.Name, stored, held, QuarantinePrefix+rest, OutcomeQuarantined)
	default:
		s.releaseLease(ctx, held)
		return objectResult{outcome: OutcomeRetry, claimed: true, senderRefused: verdict.senderRefused, status: verdict.status, errorType: verdict.errorType}, nil
	}
}

// claim takes the lease for rest. ok is false when a sibling holds it, the
// object is in backoff, or a sibling won the write.
func (s *Sweeper) claim(ctx context.Context, rest string) (claim, bool, error) {
	name := leasePrefix + rest
	now := s.now()
	var current lease
	var generation int64
	stored, err := s.store.Get(ctx, name)
	switch {
	case errors.Is(err, batch.ErrNotFound):
	case err != nil:
		return claim{}, false, err
	default:
		generation = stored.Generation
		// A lease that does not decode is treated as expired: it can only
		// be rewritten by this generation-conditional Put.
		_ = json.Unmarshal(stored.Data, &current)
		if current.Until > now.UnixMilli() {
			return claim{}, false, nil
		}
	}
	next := lease{Owner: s.owner, Until: now.Add(s.lease).UnixMilli(), Attempts: current.Attempts + 1}
	data, err := json.Marshal(next)
	if err != nil {
		return claim{}, false, err
	}
	updated, err := s.store.Put(ctx, name, data, batch.PutCondition{Generation: generation})
	if errors.Is(err, batch.ErrPrecondition) {
		return claim{}, false, nil
	}
	if err != nil {
		return claim{}, false, err
	}
	return claim{name: name, generation: updated.Generation, attempts: next.Attempts}, true, nil
}

// releaseLease ends this claim with a backoff: the object is claimable again
// once the backoff passes. The backoff doubles per attempt and never exceeds
// the lease, so a sibling can always pick the object up within one lease.
func (s *Sweeper) releaseLease(ctx context.Context, held claim) {
	next := lease{Until: s.now().Add(s.backoff(held.attempts)).UnixMilli(), Attempts: held.attempts}
	data, err := json.Marshal(next)
	if err != nil {
		return
	}
	if _, err := s.store.Put(ctx, held.name, data, batch.PutCondition{Generation: held.generation}); err != nil && !errors.Is(err, batch.ErrPrecondition) {
		s.logf("settle_outbox.sweep_release_failed owner=%q lease=%q err=%q", s.owner, held.name, err.Error())
	}
}

// dropLease removes a lease this sweeper holds. A precondition failure means
// a sibling re-leased it after ours ran out; theirs stands.
func (s *Sweeper) dropLease(ctx context.Context, held claim) {
	if err := s.store.Delete(ctx, held.name, held.generation); err != nil && !errors.Is(err, batch.ErrPrecondition) {
		s.logf("settle_outbox.sweep_lease_delete_failed owner=%q lease=%q err=%q", s.owner, held.name, err.Error())
	}
}

func (s *Sweeper) backoff(attempts int) time.Duration {
	delay := s.interval
	for i := 1; i < attempts && delay < s.lease; i++ {
		delay *= 2
	}
	return min(delay, s.lease)
}

// file moves the pending object to target, bytes unchanged: create the copy
// (an existing copy from a sibling is as good), then delete the pending
// object at the generation we read, then drop the lease. Batch's
// finishTerminal does the same for its job objects.
func (s *Sweeper) file(ctx context.Context, pendingName string, stored batch.StoredObject, held claim, target string, outcome Outcome) (objectResult, error) {
	if _, err := s.store.Put(ctx, target, stored.Data, batch.PutCondition{Generation: 0}); err != nil && !errors.Is(err, batch.ErrPrecondition) {
		// The copy failed: keep the lease so the object is retried after it
		// ends, and nothing is lost.
		s.releaseLease(ctx, held)
		return objectResult{outcome: OutcomeRetry, claimed: true}, err
	}
	if err := s.store.Delete(ctx, pendingName, stored.Generation); err != nil && !errors.Is(err, batch.ErrPrecondition) {
		// The copy exists; the pending object will be seen again and filed
		// again, which is a repeat replay the router keeps the first writer of.
		s.releaseLease(ctx, held)
		return objectResult{outcome: OutcomeRetry, claimed: true}, err
	}
	s.dropLease(ctx, held)
	s.logf("settle_outbox.sweep_filed owner=%q object=%q target=%q outcome=%q", s.owner, pendingName, target, outcome)
	return objectResult{outcome: outcome, claimed: true}, nil
}

// unverifiedReason says why an object must not be replayed as trusted, or
// "" when it carries a well-formed boot-auth header for its own boot kid. The
// sweeper cannot verify the signature (only the router holds the registered
// keys); it refuses what is plainly unsigned, as §9.2 requires, and leaves
// verification to the router at replay.
func unverifiedReason(object Object) string {
	kid, ok := bootAuthKID(object.BootAuth)
	if !ok {
		return "unsigned"
	}
	if object.BootKID != "" && object.BootKID != kid {
		return "boot_kid_mismatch"
	}
	return ""
}

// bootAuthKID parses "kid=<kid>,sig=<sig>" and reports the kid.
func bootAuthKID(header string) (string, bool) {
	kid, sig, found := strings.Cut(header, ",")
	if !found {
		return "", false
	}
	kid, hasKID := strings.CutPrefix(kid, "kid=")
	sig, hasSig := strings.CutPrefix(sig, "sig=")
	if !hasKID || !hasSig || kid == "" || sig == "" {
		return "", false
	}
	return kid, true
}

type replayVerdict struct {
	outcome       Outcome
	reason        string
	status        int
	errorType     string
	senderRefused bool
}

// refusalKind is what a 401 or 403 from the router means.
type refusalKind string

const (
	// refusalKindBootAuth: the router refused the object's boot auth (R3).
	// About the object: quarantine.
	refusalKindBootAuth refusalKind = "boot_auth_refused"
	// refusalKindSender: the router refused this sweeper's internal
	// service token. About the sender: stop the page, pause.
	refusalKindSender refusalKind = "sender_refused"
	// refusalKindSenderUnknown: a 401 or 403 that is neither. Fail safe:
	// treated as the sender's problem (retry later), never quarantine.
	refusalKindSenderUnknown refusalKind = "refused_unknown"
)

// readRefusal is the one place a 401 or 403 is interpreted. The status
// alone conflates the router refusing the sweeper's own token with the
// router refusing the object's signature; the error body tells them apart.
func readRefusal(controlErr *trustedrouter.ControlPlaneError) refusalKind {
	switch {
	case controlErr.StatusCode == http.StatusUnauthorized && controlErr.Reason == BootAuthRefusedReason:
		return refusalKindBootAuth
	case strings.Contains(strings.ToLower(controlErr.Message), senderRefusedMessage):
		return refusalKindSender
	default:
		return refusalKindSenderUnknown
	}
}

// classify maps a replay's error to an outcome per §9.2: 2xx settles; 404
// and 409 are the router's deterministic refusals of the authorization; 5xx
// and transport retry. A 401 or 403 goes through readRefusal: only the
// router refusing the object's boot auth quarantines; a refusal of the
// sweeper's own token, or one that is neither, stops the page and pauses
// (senderRefused). Another 4xx is not in the contract: 408 and 429 ask for a
// retry, the rest are deterministic and go to dead/ for a human.
func classify(err error) replayVerdict {
	if err == nil {
		return replayVerdict{outcome: OutcomeSettled, reason: "settled"}
	}
	var controlErr *trustedrouter.ControlPlaneError
	if !errors.As(err, &controlErr) {
		return replayVerdict{outcome: OutcomeRetry, reason: "transport"}
	}
	status := controlErr.StatusCode
	errorType := controlErr.Type
	switch {
	case status == http.StatusNotFound:
		return replayVerdict{outcome: OutcomeDead, reason: "unknown_authorization", status: status, errorType: errorType}
	case status == http.StatusConflict:
		return replayVerdict{outcome: OutcomeDead, reason: "retired_settlement_kind", status: status, errorType: errorType}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		kind := readRefusal(controlErr)
		if kind == refusalKindBootAuth {
			return replayVerdict{outcome: OutcomeQuarantined, reason: string(kind), status: status, errorType: errorType}
		}
		return replayVerdict{outcome: OutcomeRetry, reason: string(kind), status: status, errorType: errorType, senderRefused: true}
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests:
		return replayVerdict{outcome: OutcomeRetry, reason: "throttled", status: status, errorType: errorType}
	case status >= 400 && status < 500:
		return replayVerdict{outcome: OutcomeDead, reason: "rejected", status: status, errorType: errorType}
	default:
		return replayVerdict{outcome: OutcomeRetry, reason: "server_error", status: status, errorType: errorType}
	}
}

func disposition(result *trustedrouter.SettleResult) string {
	if result == nil {
		return ""
	}
	return result.Disposition
}

func randomOwner() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "sweeper_" + hex.EncodeToString(buffer)
}
