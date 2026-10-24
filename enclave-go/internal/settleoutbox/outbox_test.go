package settleoutbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// A body JSON re-encoding would change: HTML-escapable characters, spaces
// after separators, a key order json.Marshal would not produce, and non-ASCII.
const awkwardBody = `{"request_id": "chat<1>&2", "authorization_id":"auth_outbox_1", "z":1,"a":"é", "actual_output_tokens":3}`

func settleTerminal(body string) trustedrouter.FrozenTerminal {
	return trustedrouter.FrozenTerminal{Path: "/internal/gateway/settle", Body: []byte(body), BaseURL: "https://trustedrouter.com"}
}

type memoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    []string
	fail    func(name string, attempt int) error
	calls   map[string]int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{objects: map[string][]byte{}, calls: map[string]int{}}
}

func (s *memoryStore) Put(_ context.Context, name string, data []byte, condition batch.PutCondition) (batch.StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[name]++
	if s.fail != nil {
		if err := s.fail(name, s.calls[name]); err != nil {
			return batch.StoredObject{}, err
		}
	}
	if condition.Generation != 0 {
		return batch.StoredObject{}, errors.New("outbox must create, not overwrite")
	}
	if _, exists := s.objects[name]; exists {
		return batch.StoredObject{}, batch.ErrPrecondition
	}
	s.objects[name] = append([]byte(nil), data...)
	s.puts = append(s.puts, name)
	return batch.StoredObject{Name: name, Data: data, Generation: int64(len(s.puts))}, nil
}

func (s *memoryStore) object(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[name]
	return data, ok
}

func (s *memoryStore) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.puts...)
}

func testSigner(t *testing.T) *receipt.Signer {
	t.Helper()
	signer, err := receipt.NewSignerFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestEncodeKeepsExactBytesAndSignsReplay(t *testing.T) {
	t.Parallel()
	signer := testSigner(t)
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	entry := Entry{Terminal: settleTerminal(awkwardBody), Reason: "retry_exhausted", Attempts: 6}

	name, data, err := Encode(entry, signer, at)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, ObjectPrefix+"settle/auth_outbox_1/") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("name = %q", name)
	}
	object, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(object.Body, []byte(awkwardBody)) {
		t.Fatalf("body changed:\n got %s\nwant %s", object.Body, awkwardBody)
	}
	if got := object.Terminal(); got.Path != entry.Terminal.Path || got.BaseURL != "https://trustedrouter.com" || !bytes.Equal(got.Body, entry.Terminal.Body) {
		t.Fatalf("terminal = %+v", got)
	}
	if object.Kind != KindSettle || object.AuthorizationID != "auth_outbox_1" || object.Reason != "retry_exhausted" || object.Attempts != 6 || object.Version != Version {
		t.Fatalf("object = %+v", object)
	}
	if object.WrittenAt != "2026-10-24T12:00:00Z" {
		t.Fatalf("written_at = %q", object.WrittenAt)
	}
	// The body on the wire is base64, never re-encoded JSON.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["body"]) != `"`+base64.StdEncoding.EncodeToString([]byte(awkwardBody))+`"` {
		t.Fatalf("body field = %s", raw["body"])
	}
	for _, forbidden := range []string{"chat<1>", "actual_output_tokens"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("object carries the body in clear: %s", data)
		}
	}

	// The boot auth is exactly what the sweeper will send, verifiable with
	// the writing boot's public key over POST, the path and the body.
	if object.BootKID != signer.Kid() || !strings.HasPrefix(object.BootAuth, "kid="+signer.Kid()+",sig=") {
		t.Fatalf("boot auth = %q kid = %q", object.BootAuth, object.BootKID)
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(object.BootAuth, "kid="+signer.Kid()+",sig="))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(signer.JWK().X)
	if err != nil {
		t.Fatal(err)
	}
	digest := spendlease.AuthorizeDigest(http.MethodPost, object.Path, object.Body)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), digest[:], signature) {
		t.Fatal("boot auth does not verify over POST, path and the frozen body")
	}
	wrong := spendlease.AuthorizeDigest(http.MethodPost, object.Path, []byte(awkwardBody+" "))
	if ed25519.Verify(ed25519.PublicKey(publicKey), wrong[:], signature) {
		t.Fatal("boot auth verifies over a different body")
	}
}

func TestEncodeWithoutSignerLeavesBootAuthEmpty(t *testing.T) {
	t.Parallel()
	_, data, err := Encode(Entry{Terminal: settleTerminal(awkwardBody), Reason: "queue_full"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	object, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if object.BootAuth != "" || object.BootKID != "" {
		t.Fatalf("boot auth = %q kid = %q", object.BootAuth, object.BootKID)
	}
}

func TestEncodeKeepsAFrozenBootAuth(t *testing.T) {
	t.Parallel()
	terminal := settleTerminal(awkwardBody)
	terminal.BootAuth = "kid=original,sig=abc"
	_, data, err := Encode(Entry{Terminal: terminal}, testSigner(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	object, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if object.BootAuth != "kid=original,sig=abc" || object.BootKID != "" {
		t.Fatalf("boot auth = %q kid = %q", object.BootAuth, object.BootKID)
	}
}

func TestEncodeRefusesWhatIsNotATerminal(t *testing.T) {
	t.Parallel()
	for _, terminal := range []trustedrouter.FrozenTerminal{
		{Path: "/internal/gateway/heartbeat", Body: []byte(`{}`)},
		{Path: "/internal/gateway/settle"},
	} {
		if _, _, err := Encode(Entry{Terminal: terminal}, nil, time.Now()); err == nil {
			t.Fatalf("Encode(%+v) succeeded", terminal)
		}
	}
}

func TestObjectNameIsAFunctionOfKindAuthorizationAndBytes(t *testing.T) {
	t.Parallel()
	body := []byte(`{"authorization_id":"auth_1","actual_output_tokens":3}`)
	same := ObjectName(KindSettle, "auth_1", body)
	if same != ObjectName(KindSettle, "auth_1", append([]byte(nil), body...)) {
		t.Fatal("same bytes name different objects")
	}
	if same == ObjectName(KindSettle, "auth_1", []byte(`{"authorization_id":"auth_1","actual_output_tokens":4}`)) {
		t.Fatal("a corrected body names the same object")
	}
	if same == ObjectName(KindRefund, "auth_1", body) {
		t.Fatal("a refund for the same authorization names the settle's object")
	}
	if !strings.HasPrefix(same, ObjectPrefix+"settle/auth_1/") {
		t.Fatalf("name = %q", same)
	}
	for _, id := range []string{"", "a/b", "a b", "a?b", strings.Repeat("x", 129)} {
		if name := ObjectName(KindSettle, id, body); !strings.HasPrefix(name, ObjectPrefix+"settle/unnamed/") {
			t.Fatalf("ObjectName(%q) = %q", id, name)
		}
	}
}

func TestDecodeRefusesTamperedObjects(t *testing.T) {
	t.Parallel()
	_, data, err := Encode(Entry{Terminal: settleTerminal(awkwardBody)}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(){
		"version": func() { fields["version"] = 2 },
		"body": func() {
			fields["body"] = base64.StdEncoding.EncodeToString([]byte(`{"authorization_id":"auth_outbox_1"}`))
		},
		"path": func() { fields["path"] = "/internal/gateway/heartbeat" },
	} {
		original := fields[name]
		mutate()
		tampered, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(tampered); err == nil {
			t.Fatalf("Decode accepted a tampered %s", name)
		}
		fields[name] = original
	}
	if _, err := Decode(data); err != nil {
		t.Fatalf("Decode(untampered) = %v", err)
	}
}

func TestWriteCreatesOnceAndTreatsAnExistingObjectAsDurable(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	writer := NewWriter(store, nil, nil)
	entry := Entry{Terminal: settleTerminal(awkwardBody), Reason: "retry_exhausted", Attempts: 6}

	first, err := writer.Write(t.Context(), entry)
	if err != nil || first.AlreadyDurable {
		t.Fatalf("first Write = %+v, %v", first, err)
	}
	second, err := writer.Write(t.Context(), entry)
	if err != nil || !second.AlreadyDurable || second.Name != first.Name {
		t.Fatalf("second Write = %+v, %v", second, err)
	}
	if names := store.names(); len(names) != 1 || names[0] != first.Name {
		t.Fatalf("puts = %v", names)
	}
	data, _ := store.object(first.Name)
	object, err := Decode(data)
	if err != nil || !bytes.Equal(object.Body, []byte(awkwardBody)) {
		t.Fatalf("stored object = %+v, %v", object, err)
	}
}

func TestWriteReportsOtherStoreErrors(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	store.fail = func(string, int) error { return errors.New("gcs put status 503") }
	_, err := NewWriter(store, nil, nil).Write(t.Context(), Entry{Terminal: settleTerminal(awkwardBody)})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("Write = %v", err)
	}
}

func TestQueuedWritesRetryTransientErrorsThenLand(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	store.fail = func(_ string, attempt int) error {
		if attempt < 3 {
			return errors.New("gcs put status 503")
		}
		return nil
	}
	var logs []string
	var logMu sync.Mutex
	writer := NewWriter(store, testSigner(t), func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, strings.SplitN(format, " ", 2)[0])
	})
	writer.retryDelay = time.Millisecond
	writer.Start(t.Context())
	if !writer.Offer(Entry{Terminal: settleTerminal(awkwardBody), Reason: "shutdown", Attempts: 2}) {
		t.Fatal("Offer refused")
	}
	flushCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := writer.Flush(flushCtx); err != nil {
		t.Fatal(err)
	}
	if names := store.names(); len(names) != 1 {
		t.Fatalf("puts = %v", names)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if want := []string{"settle_outbox.write_failed", "settle_outbox.write_failed", "settle_outbox.written"}; strings.Join(logs, ",") != strings.Join(want, ",") {
		t.Fatalf("logs = %v", logs)
	}
}

func TestQueuedWriteGivesUpAfterThreeAttempts(t *testing.T) {
	t.Parallel()
	store := newMemoryStore()
	store.fail = func(string, int) error { return errors.New("gcs put status 503") }
	var lost int
	var logMu sync.Mutex
	writer := NewWriter(store, nil, func(format string, _ ...any) {
		if strings.HasPrefix(format, "settle_outbox.lost") {
			logMu.Lock()
			lost++
			logMu.Unlock()
		}
	})
	writer.retryDelay = time.Millisecond
	writer.Start(t.Context())
	writer.Offer(Entry{Terminal: settleTerminal(awkwardBody)})
	flushCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := writer.Flush(flushCtx); err != nil {
		t.Fatal(err)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if lost != 1 || store.calls[ObjectName(KindSettle, "auth_outbox_1", []byte(awkwardBody))] != writeAttempts {
		t.Fatalf("lost = %d calls = %v", lost, store.calls)
	}
}

func TestOfferDropsWhenTheQueueIsFull(t *testing.T) {
	t.Parallel()
	writer := NewWriter(newMemoryStore(), nil, nil)
	writer.queue = make(chan Entry, 1)
	// Not started: the first entry fills the queue, the second is refused.
	if !writer.Offer(Entry{Terminal: settleTerminal(awkwardBody)}) {
		t.Fatal("first Offer refused")
	}
	if writer.Offer(Entry{Terminal: settleTerminal(awkwardBody)}) {
		t.Fatal("second Offer accepted by a full queue")
	}
	if writer.Pending() != 1 || writer.dropped != 1 {
		t.Fatalf("pending = %d dropped = %d", writer.Pending(), writer.dropped)
	}
	flushCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := writer.Flush(flushCtx); err == nil {
		t.Fatal("Flush reported an unwritten entry as flushed")
	}
}

func TestNilWriterIsInert(t *testing.T) {
	t.Parallel()
	var writer *Writer
	writer.Start(t.Context())
	if writer.Offer(Entry{Terminal: settleTerminal(awkwardBody)}) {
		t.Fatal("nil writer accepted an entry")
	}
	if err := writer.Flush(t.Context()); err != nil || writer.Pending() != 0 {
		t.Fatalf("Flush = %v pending = %d", err, writer.Pending())
	}
	if _, err := writer.Write(t.Context(), Entry{Terminal: settleTerminal(awkwardBody)}); err == nil {
		t.Fatal("nil writer wrote")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

type fixedToken string

func (token fixedToken) Token(context.Context) (string, error) { return string(token), nil }

// The real GCS client: a create-only upload of the encoded object, and a
// 412 read as already durable.
func TestWriteThroughGCSStoreIsCreateOnly(t *testing.T) {
	t.Parallel()
	var requests []*http.Request
	var bodies [][]byte
	var mu sync.Mutex
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(request.Body)
		mu.Lock()
		requests = append(requests, request)
		bodies = append(bodies, raw)
		n := len(requests)
		mu.Unlock()
		if n == 2 {
			return &http.Response{StatusCode: http.StatusPreconditionFailed, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"generation":"7"}`))}, nil
	})}
	store := batch.NewGCSStoreForTest("outbox-bucket", client, fixedToken("federated-token"))
	writer := NewWriter(store, nil, nil)
	entry := Entry{Terminal: settleTerminal(awkwardBody), Reason: "retry_exhausted"}

	first, err := writer.Write(t.Context(), entry)
	if err != nil || first.AlreadyDurable {
		t.Fatalf("first Write = %+v, %v", first, err)
	}
	second, err := writer.Write(t.Context(), entry)
	if err != nil || !second.AlreadyDurable {
		t.Fatalf("second Write = %+v, %v", second, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("requests = %d", len(requests))
	}
	for _, request := range requests {
		if request.Method != http.MethodPost || request.URL.Host != "storage.googleapis.com" ||
			!strings.HasPrefix(request.URL.Path, "/upload/storage/v1/b/outbox-bucket/o") ||
			request.URL.Query().Get("ifGenerationMatch") != "0" || request.URL.Query().Get("name") != first.Name ||
			request.Header.Get("Authorization") != "Bearer federated-token" {
			t.Fatalf("request = %s %s %v", request.Method, request.URL, request.Header)
		}
	}
	object, err := Decode(bodies[0])
	if err != nil || !bytes.Equal(object.Body, []byte(awkwardBody)) {
		t.Fatalf("uploaded object = %+v, %v", object, err)
	}
}
