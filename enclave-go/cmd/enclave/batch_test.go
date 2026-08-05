package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type routeBatchStore struct {
	mu      sync.Mutex
	next    int64
	objects map[string]batchapi.StoredObject
}

func newRouteBatchStore() *routeBatchStore {
	return &routeBatchStore{next: 1, objects: map[string]batchapi.StoredObject{}}
}

func (s *routeBatchStore) Get(_ context.Context, name string) (batchapi.StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[name]
	if !ok {
		return batchapi.StoredObject{}, batchapi.ErrNotFound
	}
	object.Data = append([]byte(nil), object.Data...)
	return object, nil
}

func (s *routeBatchStore) Put(_ context.Context, name string, data []byte, condition batchapi.PutCondition) (batchapi.StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.objects[name]
	if condition.Generation == 0 && exists {
		return batchapi.StoredObject{}, batchapi.ErrPrecondition
	}
	if condition.Generation > 0 && (!exists || existing.Generation != condition.Generation) {
		return batchapi.StoredObject{}, batchapi.ErrPrecondition
	}
	object := batchapi.StoredObject{Name: name, Data: append([]byte(nil), data...), Generation: s.next}
	s.next++
	s.objects[name] = object
	return object, nil
}

func (s *routeBatchStore) Delete(_ context.Context, name string, generation int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[name]
	if ok && generation > 0 && object.Generation != generation {
		return batchapi.ErrPrecondition
	}
	delete(s.objects, name)
	return nil
}

func (s *routeBatchStore) List(
	_ context.Context,
	prefix string,
	limit int,
	pageToken string,
) ([]batchapi.ObjectMeta, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for name := range s.objects {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if pageToken != "" {
		start := sort.SearchStrings(names, pageToken)
		if start < len(names) && names[start] == pageToken {
			start++
		}
		names = names[start:]
	}
	nextPageToken := ""
	if limit > 0 && len(names) > limit {
		nextPageToken = names[limit-1]
		names = names[:limit]
	}
	objects := make([]batchapi.ObjectMeta, 0, len(names))
	for _, name := range names {
		objects = append(objects, batchapi.ObjectMeta{Name: name, Generation: s.objects[name].Generation})
	}
	return objects, nextPageToken, nil
}

type routeBatchProtector struct{}

func (routeBatchProtector) Seal(_ context.Context, _, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (routeBatchProtector) Open(_ context.Context, _, _ string, encoded []byte) ([]byte, error) {
	return append([]byte(nil), encoded...), nil
}

type routeBatchKeys struct{}

func (routeBatchKeys) ValidateKey(_ context.Context, bearer, _ string) error {
	if bearer != "owner-key" {
		return errors.New("invalid key")
	}
	return nil
}

type routeBatchExecutor struct{}

func (routeBatchExecutor) Execute(context.Context, string, string, []byte, string) (int, string, []byte, error) {
	return 500, "", nil, errors.New("route test executor should not run")
}

func testBatchGateway(t *testing.T) *batchapi.Service {
	t.Helper()
	service, err := batchapi.New(batchapi.Options{
		Store:        newRouteBatchStore(),
		Protector:    routeBatchProtector{},
		Keys:         routeBatchKeys{},
		Executor:     routeBatchExecutor{},
		WorkerID:     "route-test",
		PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("batch.New: %v", err)
	}
	return service
}

func batchHTTPBody(t *testing.T, response string) []byte {
	t.Helper()
	parts := strings.SplitN(response, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid HTTP response: %q", response)
	}
	return []byte(parts[1])
}

func chunkedBatchHTTPBody(t *testing.T, response string) []byte {
	t.Helper()
	parts := strings.SplitN(response, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid HTTP response: %q", response)
	}
	body, err := io.ReadAll(httputil.NewChunkedReader(strings.NewReader(parts[1])))
	if err != nil {
		t.Fatalf("decode chunked response: %v", err)
	}
	return body
}

func TestMaybeServeBatchRouteCreateAndGet(t *testing.T) {
	previous := batchGateway
	batchGateway = testBatchGateway(t)
	t.Cleanup(func() { batchGateway = previous })

	body := []byte(`{"endpoint":"/v1/chat/completions","model":"test/model","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"hello"}]}}]}`)
	var create bytes.Buffer
	if !maybeServeBatchRoute(t.Context(), &create, http.MethodPost, "/api/beta/batches", body, "owner-key") {
		t.Fatal("batch create route was not handled")
	}
	if !strings.Contains(create.String(), "HTTP/1.1 202 Accepted") {
		t.Fatalf("create response = %q", create.String())
	}
	var created batchapi.Batch
	if err := json.Unmarshal(batchHTTPBody(t, create.String()), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if !strings.HasPrefix(created.ID, "batch_") || created.Object != "batch" || created.Status != "validating" || created.CompletionWindow != "24h" || created.Results != nil || created.Usage != nil {
		t.Fatalf("created = %#v", created)
	}

	var get bytes.Buffer
	if !maybeServeBatchRoute(t.Context(), &get, http.MethodGet, "/api/beta/batches/"+created.ID, nil, "owner-key") {
		t.Fatal("batch get route was not handled")
	}
	if !strings.Contains(get.String(), "HTTP/1.1 200 OK") {
		t.Fatalf("get response = %q", get.String())
	}
	var fetched batchapi.Batch
	if err := json.Unmarshal(batchHTTPBody(t, get.String()), &fetched); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if fetched.ID != created.ID || fetched.Status != "validating" {
		t.Fatalf("fetched = %#v", fetched)
	}
}

func TestCompletedBatchRouteStreamsValidOrderedJSON(t *testing.T) {
	previous := batchGateway
	batchGateway = testBatchGateway(t)
	t.Cleanup(func() { batchGateway = previous })
	batchGateway.Start(t.Context())

	created, apiErr := batchGateway.Create(
		t.Context(),
		"owner-key",
		[]byte(`{"endpoint":"/v1/chat/completions","model":"test/model","requests":[{"custom_id":"one","body":{"messages":[{"role":"user","content":"hello"}]}},{"custom_id":"two","body":{"messages":[{"role":"user","content":"world"}]}}]}`),
	)
	if apiErr != nil {
		t.Fatalf("create: %#v", apiErr)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		prepared, getErr := batchGateway.PrepareGet(t.Context(), "owner-key", created.ID)
		if getErr != nil {
			t.Fatalf("prepare get: %#v", getErr)
		}
		if prepared.Batch.Status == batchapi.StatusCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("batch remained %q", prepared.Batch.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}

	var response bytes.Buffer
	if !maybeServeBatchRoute(
		t.Context(), &response, http.MethodGet,
		"/api/beta/batches/"+created.ID, nil, "owner-key",
	) {
		t.Fatal("completed batch route was not handled")
	}
	if !strings.Contains(response.String(), "Transfer-Encoding: chunked") {
		t.Fatalf("response did not stream: %q", response.String())
	}
	var fetched batchapi.Batch
	if err := json.Unmarshal(chunkedBatchHTTPBody(t, response.String()), &fetched); err != nil {
		t.Fatalf("decode streamed batch: %v", err)
	}
	if fetched.Status != batchapi.StatusCompleted || len(fetched.Results) != 2 ||
		fetched.Results[0].CustomID != "one" || fetched.Results[1].CustomID != "two" {
		t.Fatalf("fetched = %#v", fetched)
	}
}

func TestMaybeServeBatchRouteReturnsStableErrors(t *testing.T) {
	previous := batchGateway
	t.Cleanup(func() { batchGateway = previous })

	tests := []struct {
		name    string
		service *batchapi.Service
		method  string
		path    string
		body    []byte
		status  string
		code    string
	}{
		{"disabled", nil, http.MethodPost, "/api/beta/batches", []byte(`{}`), "503 Service Unavailable", "batch_unavailable"},
		{"bad method", testBatchGateway(t), http.MethodGet, "/api/beta/batches", nil, "404 Not Found", "not_found"},
		{"bad order", testBatchGateway(t), http.MethodPost, "/api/beta/batches", []byte(`{"requests":[],"endpoint":"/v1/messages","model":"m"}`), "400 Bad Request", "bad_request"},
		{"nested path", testBatchGateway(t), http.MethodGet, "/api/beta/batches/batch_x/extra", nil, "404 Not Found", "not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batchGateway = test.service
			var response bytes.Buffer
			if !maybeServeBatchRoute(t.Context(), &response, test.method, test.path, test.body, "owner-key") {
				t.Fatal("route was not handled")
			}
			if !strings.Contains(response.String(), "HTTP/1.1 "+test.status) || !bytes.Contains(batchHTTPBody(t, response.String()), []byte(`"code":"`+test.code+`"`)) {
				t.Fatalf("response = %q", response.String())
			}
		})
	}
}

func TestBatchEnclaveExecutorUsesOrdinaryAuthorizeInvokeAndSettlePath(t *testing.T) {
	bearer := "private-batch-bearer"
	lookupHash := trustedrouter.LookupHash(bearer)
	prompt := "private batch prompt"
	idempotencyKey := "tr-batch:batch_0123456789abcdef0123456789abcdef:0"
	var authorizeCalls int
	var settleCalls int
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read control-plane request: %v", err)
		}
		if bytes.Contains(body, []byte(bearer)) || bytes.Contains(body, []byte(prompt)) {
			t.Fatalf("control plane received batch content: %s", body)
		}
		switch request.URL.Path {
		case "/internal/gateway/authorize":
			authorizeCalls++
			if !bytes.Contains(body, []byte(`"api_key_lookup_hash":"`+lookupHash+`"`)) {
				t.Fatalf("authorize did not receive persisted lookup hash: %s", body)
			}
			if !bytes.Contains(body, []byte(`"idempotency_key":"`+idempotencyKey+`"`)) {
				t.Fatalf("authorize did not receive item idempotency key: %s", body)
			}
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_batch","workspace_id":"ws_1","api_key_hash":"key_1","model":"test/model","endpoint_id":"test/model@test/prepaid","provider":"test","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case "/internal/gateway/settle":
			settleCalls++
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_batch","cost_microdollars":9,"model":"test/model","provider":"test","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", request.URL.Path)
		}
	}))
	defer controlPlane.Close()

	executor := &batchEnclaveExecutor{
		registry: auth.New(nil),
		backend:  &fakeStreamingLLM{},
		gateway:  trustedrouter.New(controlPlane.URL, "internal-token", controlPlane.Client()),
	}
	body := []byte(`{"model":"test/model","stream":false,"messages":[{"role":"user","content":"` + prompt + `"}],"max_tokens":32}`)
	status, _, responseBody, err := executor.Execute(
		t.Context(), lookupHash, "/v1/chat/completions", body, idempotencyKey,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if status != http.StatusOK || !bytes.Contains(responseBody, []byte("Hello world")) {
		t.Fatalf("status=%d body=%s", status, responseBody)
	}
	if authorizeCalls != 1 || settleCalls != 1 {
		t.Fatalf("authorize=%d settle=%d", authorizeCalls, settleCalls)
	}
}
