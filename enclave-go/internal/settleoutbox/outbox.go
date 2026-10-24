// Package settleoutbox is the enclave half of the durable settle outbox
// (quill-router docs/design/durable-settle-outbox.md §9,
// fast-admission-enclave-direct.md §3 E4): a settle or refund the enclave
// could not deliver is written as a GCS object so a later sweeper, running in
// a sibling enclave, can replay it. The object carries the frozen terminal's
// exact bytes, the authority that holds the authorization, and the boot-auth
// header the writing boot computed for that replay. The sweeper is not in
// this package.
//
// Nothing here is reached unless an object store is configured. The object
// body is the frozen terminal, which carries no prompt, output, key or token.
package settleoutbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const (
	// Version is the object envelope version. A sweeper refuses what it does
	// not know.
	Version = 1
	// ObjectPrefix is where pending objects live. The sweeper lists it.
	ObjectPrefix = "trustedrouter-settle-outbox/v1/pending/"

	KindSettle = "settle"
	KindRefund = "refund"

	defaultQueueSize    = 4096
	defaultWriteTimeout = 20 * time.Second
	writeAttempts       = 3
	writeRetryDelay     = 500 * time.Millisecond
)

// ObjectStore is the create-only slice of batch.ObjectStore the outbox uses.
// *batch.GCSStore satisfies it.
type ObjectStore interface {
	Put(context.Context, string, []byte, batch.PutCondition) (batch.StoredObject, error)
}

// Entry is one terminal to park, and why.
type Entry struct {
	Terminal trustedrouter.FrozenTerminal
	// Reason names the failure path: retry_exhausted, queue_full, evicted,
	// queue_disabled or shutdown. It is metadata for the sweeper's logs.
	Reason string
	// Attempts is how many deliveries the enclave tried before parking.
	Attempts int
}

// Object is the envelope written to the store.
type Object struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	// Path and Body are the frozen terminal: the replay posts exactly Body
	// to BaseURL+Path. Body is base64 on the wire so the bytes survive any
	// JSON re-encoding untouched.
	Path       string `json:"path"`
	Body       []byte `json:"body"`
	BodySHA256 string `json:"body_sha256"`
	// BaseURL is the billing authority that holds the authorization, or
	// empty when the original send was unpinned.
	BaseURL string `json:"base_url,omitempty"`
	// BootAuth is the X-TR-Boot-Auth header value for the replay: the
	// writing boot's signature over POST, Path and Body
	// (spendlease.AuthorizeDigest), so a sibling enclave can replay without
	// this boot's key. The writer signs only with a boot key the control
	// plane was told about at registration (Client.RegisteredBootSigner);
	// otherwise it is empty, and an object without it is unverified: the
	// sweeper must not replay it as trusted.
	BootAuth string `json:"boot_auth,omitempty"`
	BootKID  string `json:"boot_kid,omitempty"`

	AuthorizationID string `json:"authorization_id,omitempty"`
	Reason          string `json:"reason"`
	Attempts        int    `json:"attempts"`
	WrittenAt       string `json:"written_at"`
}

// Kind names the terminal a path carries.
func Kind(path string) (string, error) {
	switch path {
	case "/internal/gateway/settle":
		return KindSettle, nil
	case "/internal/gateway/refund":
		return KindRefund, nil
	default:
		return "", fmt.Errorf("settleoutbox: path %q is not a settle or refund", path)
	}
}

// ObjectName is the pending object for a terminal. It is a function of the
// kind, the authorization and the exact body, so the same terminal parked
// twice is one object and a corrected body is another; both replay
// idempotently at the router, which keeps the first writer.
func ObjectName(kind, authorizationID string, body []byte) string {
	digest := sha256.Sum256(body)
	id := strings.TrimSpace(authorizationID)
	if id == "" || strings.ContainsAny(id, "/\\?#%\n\r\t ") || len(id) > 128 {
		id = "unnamed"
	}
	return ObjectPrefix + kind + "/" + id + "/" + hex.EncodeToString(digest[:16]) + ".json"
}

// Encode builds the object for entry, signing the replay with signer when one
// is given. It returns the object's name and its bytes.
func Encode(entry Entry, signer spendlease.DigestSigner, now time.Time) (string, []byte, error) {
	kind, err := Kind(entry.Terminal.Path)
	if err != nil {
		return "", nil, err
	}
	if len(entry.Terminal.Body) == 0 {
		return "", nil, errors.New("settleoutbox: empty terminal body")
	}
	digest := sha256.Sum256(entry.Terminal.Body)
	object := Object{
		Version:         Version,
		Kind:            kind,
		Path:            entry.Terminal.Path,
		Body:            entry.Terminal.Body,
		BodySHA256:      hex.EncodeToString(digest[:]),
		BaseURL:         entry.Terminal.BaseURL,
		BootAuth:        entry.Terminal.BootAuth,
		AuthorizationID: authorizationID(entry.Terminal.Body),
		Reason:          entry.Reason,
		Attempts:        entry.Attempts,
		WrittenAt:       now.UTC().Format(time.RFC3339Nano),
	}
	if object.BootAuth == "" && signer != nil && signer.Kid() != "" {
		auth, err := spendlease.SignAuthorize(signer, http.MethodPost, entry.Terminal.Path, entry.Terminal.Body)
		if err != nil {
			return "", nil, fmt.Errorf("settleoutbox: sign replay: %w", err)
		}
		object.BootAuth = auth.HeaderValue()
		object.BootKID = auth.KID
	}
	data, err := json.Marshal(object)
	if err != nil {
		return "", nil, err
	}
	return ObjectName(kind, object.AuthorizationID, entry.Terminal.Body), data, nil
}

// Decode reads an object and checks its body digest. The sweeper and the
// tests use it.
func Decode(data []byte) (Object, error) {
	var object Object
	if err := json.Unmarshal(data, &object); err != nil {
		return Object{}, err
	}
	if object.Version != Version {
		return Object{}, fmt.Errorf("settleoutbox: object version %d is not %d", object.Version, Version)
	}
	if _, err := Kind(object.Path); err != nil {
		return Object{}, err
	}
	digest := sha256.Sum256(object.Body)
	if object.BodySHA256 != hex.EncodeToString(digest[:]) {
		return Object{}, errors.New("settleoutbox: body digest mismatch")
	}
	return object, nil
}

// Terminal rebuilds the frozen terminal an object holds.
func (o Object) Terminal() trustedrouter.FrozenTerminal {
	return trustedrouter.FrozenTerminal{Path: o.Path, Body: o.Body, BaseURL: o.BaseURL, BootAuth: o.BootAuth}
}

func authorizationID(body []byte) string {
	var fields struct {
		AuthorizationID string `json:"authorization_id"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return ""
	}
	return fields.AuthorizationID
}

// Result is what one write did.
type Result struct {
	Name string
	// AlreadyDurable is true when the object existed with this name: the
	// same terminal was parked before, which is as good as writing it.
	AlreadyDurable bool
}

// Writer parks terminals in an object store. Writes are queued and done by
// one goroutine so no request or retry path waits on GCS.
type Writer struct {
	store  ObjectStore
	signer spendlease.DigestSigner
	logf   func(string, ...any)
	now    func() time.Time

	writeTimeout time.Duration
	retryDelay   time.Duration

	startOnce sync.Once
	queue     chan Entry
	// pending counts entries offered and not yet written, so Flush can wait
	// for the one the goroutine holds as well as the ones in queue.
	pendingMu sync.Mutex
	pending   int
	drained   *sync.Cond
	dropped   int
}

// NewWriter returns a writer over store. signer may be nil (no boot auth in
// the objects); logf may be nil.
func NewWriter(store ObjectStore, signer spendlease.DigestSigner, logf func(string, ...any)) *Writer {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	w := &Writer{
		store:        store,
		signer:       signer,
		logf:         logf,
		now:          time.Now,
		writeTimeout: defaultWriteTimeout,
		retryDelay:   writeRetryDelay,
		queue:        make(chan Entry, defaultQueueSize),
	}
	w.drained = sync.NewCond(&w.pendingMu)
	return w
}

// Write parks one entry now. A 412 from the store means the object exists.
func (w *Writer) Write(ctx context.Context, entry Entry) (Result, error) {
	if w == nil || w.store == nil {
		return Result{}, errors.New("settleoutbox: no store")
	}
	name, data, err := Encode(entry, w.signer, w.now())
	if err != nil {
		return Result{}, err
	}
	_, err = w.store.Put(ctx, name, data, batch.PutCondition{Generation: 0})
	switch {
	case err == nil:
		return Result{Name: name}, nil
	case errors.Is(err, batch.ErrPrecondition):
		return Result{Name: name, AlreadyDurable: true}, nil
	default:
		return Result{Name: name}, err
	}
}

// Start runs the write goroutine until ctx ends.
func (w *Writer) Start(ctx context.Context) {
	if w == nil {
		return
	}
	w.startOnce.Do(func() { go w.run(ctx) })
}

// Offer queues entry without blocking. It reports false, and logs, when the
// queue is full: the terminal is then lost as it was before the outbox.
func (w *Writer) Offer(entry Entry) bool {
	if w == nil {
		return false
	}
	w.pendingMu.Lock()
	w.pending++
	w.pendingMu.Unlock()
	select {
	case w.queue <- entry:
		return true
	default:
	}
	w.pendingMu.Lock()
	w.pending--
	w.dropped++
	w.pendingMu.Unlock()
	w.logf("settle_outbox.drop auth_id=%q kind=%q reason=%q queue_full=true", authorizationID(entry.Terminal.Body), kindOf(entry.Terminal.Path), entry.Reason)
	return false
}

// Flush waits until every offered entry has been written or given up on, or
// until ctx ends. Call it at shutdown after the retry queue has drained.
func (w *Writer) Flush(ctx context.Context) error {
	if w == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		w.pendingMu.Lock()
		for w.pending > 0 {
			w.drained.Wait()
		}
		w.pendingMu.Unlock()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		w.pendingMu.Lock()
		left := w.pending
		w.pendingMu.Unlock()
		return fmt.Errorf("settleoutbox: %d entries still pending: %w", left, ctx.Err())
	}
}

// Pending reports entries offered and not yet written.
func (w *Writer) Pending() int {
	if w == nil {
		return 0
	}
	w.pendingMu.Lock()
	defer w.pendingMu.Unlock()
	return w.pending
}

func (w *Writer) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-w.queue:
			w.writeWithRetry(ctx, entry)
			w.pendingMu.Lock()
			w.pending--
			w.drained.Broadcast()
			w.pendingMu.Unlock()
		}
	}
}

func (w *Writer) writeWithRetry(ctx context.Context, entry Entry) {
	authID := authorizationID(entry.Terminal.Body)
	kind := kindOf(entry.Terminal.Path)
	for attempt := 1; attempt <= writeAttempts; attempt++ {
		writeCtx, cancel := context.WithTimeout(ctx, w.writeTimeout)
		result, err := w.Write(writeCtx, entry)
		cancel()
		if err == nil {
			w.logf("settle_outbox.written object=%q auth_id=%q kind=%q reason=%q attempts=%d already_durable=%t",
				result.Name, authID, kind, entry.Reason, entry.Attempts, result.AlreadyDurable)
			return
		}
		w.logf("settle_outbox.write_failed auth_id=%q kind=%q reason=%q write_attempt=%d err=%q",
			authID, kind, entry.Reason, attempt, err.Error())
		if attempt == writeAttempts || ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(w.retryDelay * time.Duration(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	w.logf("settle_outbox.lost auth_id=%q kind=%q reason=%q", authID, kind, entry.Reason)
}

func kindOf(path string) string {
	kind, err := Kind(path)
	if err != nil {
		return ""
	}
	return kind
}
