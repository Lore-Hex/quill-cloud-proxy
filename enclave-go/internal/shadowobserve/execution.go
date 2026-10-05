package shadowobserve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

type Route struct{ Endpoint, Provider, Model string }
type Attempt struct {
	Ordinal  int           `json:"ordinal"`
	Interval Interval      `json:"interval"`
	Status   int           `json:"status"`
	Timing   *RouterTiming `json:"router_timing"`
}

// Record is the telemetry allowlist. No generic maps, request objects, headers,
// errors, grants, credentials, prepared bytes or prompts can enter the queue.
type Record struct {
	Identity             *Identity      `json:"identity,omitempty"`
	Dropped              uint64         `json:"dropped_observations"`
	Kind                 string         `json:"kind"`
	ObservationID        string         `json:"observation_id"`
	ExecutionID          string         `json:"execution_id,omitempty"`
	DenialID             string         `json:"denial_id,omitempty"`
	Status               int            `json:"status,omitempty"`
	OriginalDenialID     string         `json:"original_denial_id,omitempty"`
	Plane                string         `json:"plane"`
	Region               string         `json:"region"`
	RouterSHA            string         `json:"router_sha"`
	EnclaveSHA           string         `json:"enclave_sha"`
	InvocationNonce      string         `json:"invocation_nonce,omitempty"`
	AuthorizationID      string         `json:"authorization_id,omitempty"`
	Decision             *Decision      `json:"predecision,omitempty"`
	Miss                 *Miss          `json:"miss,omitempty"`
	Attempts             []Attempt      `json:"attempts,omitempty"`
	Authorize            *Interval      `json:"authorize,omitempty"`
	Provider             *Interval      `json:"provider,omitempty"`
	FirstContent         *time.Duration `json:"first_content_ns"`
	ClientFirstContent   *time.Duration `json:"client_first_content_ns"`
	MeasuredP            *time.Duration `json:"measured_p_ns"`
	ActualOverlap        time.Duration  `json:"actual_authorize_provider_overlap_ns"`
	Counterfactual       *time.Duration `json:"counterfactual_min_a_p_ns"`
	PredictionProvenance string         `json:"prediction_provenance"`
	Applicability        string         `json:"durable_denial_send_spool_adoption_handoff"`
	CapacityEvidence     string         `json:"capacity_evidence"`
}
type Execution struct {
	Boundary
	mu                             sync.Mutex
	c                              Host
	id                             string
	identity                       Identity
	decision                       Decision
	route                          Route
	nonce, authorization, denialID string
	status                         int
	attempts                       []Attempt
	authorize                      *Interval
	provider                       *Interval
	firstContent, clientContent    *time.Duration
	authorized, matching, finished bool
	providerSucceeded              bool
	providerDone                   bool
}

// Host owns the monotonic clock and bounded observation queue.
type Host interface {
	Mono() time.Duration
	Emit(Record)
	Release(Identity, string)
}

func NewExecution(c Host, id string, d Decision, identity Identity, route Route) *Execution {
	x := &Execution{c: c, id: id, decision: d, identity: identity, route: route}
	c.Emit(Record{Kind: "predecision", ObservationID: NewID(), ExecutionID: id, Decision: &d, Applicability: "not-applicable", CapacityEvidence: "simulation"})
	return x
}

type executionKey struct{}

func WithExecution(ctx context.Context, x *Execution) context.Context {
	if x == nil {
		return ctx
	}
	return context.WithValue(ctx, executionKey{}, x)
}
func FromContext(ctx context.Context) *Execution {
	if ctx == nil {
		return nil
	}
	x, _ := ctx.Value(executionKey{}).(*Execution)
	return x
}
func (x *Execution) recoverObservation() {
	if recover() != nil {
		x.Fault()
		if host, ok := x.c.(interface{ Fault() }); ok {
			Protect(&x.Boundary, host.Fault)
		}
	}
}
func (x *Execution) Decision() Decision {
	x.mu.Lock()
	defer x.mu.Unlock()
	d := x.decision
	if d.Ordinal != nil {
		v := *d.Ordinal
		d.Ordinal = &v
	}
	return d
}
func (x *Execution) StartAuthorize(nonce, denialID string) {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	x.mu.Lock()
	defer x.mu.Unlock()
	x.nonce = nonce
	x.denialID = denialID
	x.authorize = &Interval{Start: x.c.Mono()}

}
func (x *Execution) EndAuthorize(id string, status int) {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	defer x.c.Release(x.identity, x.id)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.authorize != nil {
		x.authorize.End = x.c.Mono()
	}
	x.authorization = id
	x.status = status
	x.authorized = status == 200
}
func (x *Execution) Now() time.Duration {
	if x == nil {
		return 0
	}
	defer x.recoverObservation()
	return x.c.Mono()
}
func (x *Execution) ObserveAttempt(start time.Duration, status int, timing *RouterTiming) {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.attempts) < 16 {
		x.attempts = append(x.attempts, Attempt{len(x.attempts) + 1, Interval{start, x.c.Mono()}, status, timing})
	}
}
func (x *Execution) ProviderStart(route Route, first bool) {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	x.mu.Lock()
	defer x.mu.Unlock()
	x.providerSucceeded = false
	x.providerDone = false
	x.matching = x.authorized && first && x.decision.Eligible && route == x.route
	if x.matching {
		x.provider = &Interval{Start: x.c.Mono()}
	} else {
		x.provider = nil
		x.firstContent = nil
	}
}
func (x *Execution) ProviderEnd(success bool) {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	x.mu.Lock()
	defer x.mu.Unlock()
	x.providerSucceeded = success
	x.providerDone = true
	if x.provider != nil {
		x.provider.End = x.c.Mono()
	}
}
func (x *Execution) Content(client bool) {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.matching || x.provider == nil {
		return
	}
	now := x.c.Mono()
	if client {
		if x.clientContent == nil {
			x.clientContent = &now
		}
	} else if x.firstContent == nil {
		x.firstContent = &now
	}
}
func (x *Execution) Finish() {
	if x == nil {
		return
	}
	defer x.recoverObservation()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.finished {
		return
	}
	x.finished = true
	x.c.Release(x.identity, x.id)
	d := x.decision
	r := Record{Kind: "execution", Status: x.status, DenialID: x.denialID, ObservationID: NewID(), ExecutionID: x.id, InvocationNonce: x.nonce, AuthorizationID: x.authorization, Decision: &d, Attempts: append([]Attempt(nil), x.attempts...), Authorize: x.authorize, Provider: x.provider, FirstContent: x.firstContent, ClientFirstContent: x.clientContent, Applicability: "not-applicable", CapacityEvidence: "simulation", PredictionProvenance: "unknown"}
	if x.authorized && x.matching && x.providerSucceeded && x.provider != nil && x.firstContent != nil && x.authorize != nil {
		p := *x.firstContent - x.provider.Start
		if p >= 0 {
			r.MeasuredP = &p
			gain := min(max(0, x.authorize.End-x.authorize.Start), p)
			r.Counterfactual = &gain
			r.PredictionProvenance = "matching-ordinary-first-route"
		}
	}
	// Freeze interval copies: a disconnected request can finish while an
	// ordinary provider goroutine is still unwinding.
	if r.Authorize != nil {
		v := *r.Authorize
		r.Authorize = &v
	}
	if r.Provider != nil && !x.providerDone {
		r.Provider = nil
	}
	if r.Provider != nil {
		v := *r.Provider
		r.Provider = &v
	}
	// All provider calls in shadow follow authorize. The counterfactual is not
	// observed overlap and denied calls never acquire a measured provider sample.
	r.ActualOverlap = 0
	x.c.Emit(r)
}

// ContentStream recognizes content, not SSE metadata or the first socket byte.
// It retains at most one bounded line, never emits or queues its bytes.
type ContentStream struct {
	line     []byte
	overflow bool
	seen     bool
}

func (s *ContentStream) Feed(p []byte) bool {
	if s.seen {
		return false
	}
	for _, b := range p {
		if b == '\n' {
			if !s.overflow && len(s.line) > 5 && string(s.line[:5]) == "data:" && contentJSON(s.line[5:]) {
				s.seen = true
				s.line = nil
				return true
			}
			s.line = s.line[:0]
			s.overflow = false
		} else if len(s.line) < 65536 {
			s.line = append(s.line, b)
		} else {
			s.overflow = true
		}
	}
	return false
}
func contentJSON(b []byte) bool {
	var e struct {
		Type  string `json:"type"`
		Delta struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"delta"`
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal(b, &e) != nil {
		return false
	}
	if e.Type == "content_block_delta" && e.Delta.Type == "text_delta" && e.Delta.Text != "" {
		return true
	}
	for _, c := range e.Choices {
		if c.Delta.Content != "" {
			return true
		}
	}
	return false
}
