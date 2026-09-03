package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	replayCallerNonce     = "ffffffffffffffffffffffffffffffff"
	replayTestRequestBody = `{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"hello"}],"max_tokens":32}`
)

type replayAuthorizationRecord struct {
	authorizationID string
	nonce           string
}

type replayRouterDouble struct {
	mu                  sync.Mutex
	records             map[string]replayAuthorizationRecord
	authorizeAttempts   map[string]int
	authorizeNonces     map[string][]string
	settlements         int
	firstAttempt503     bool
	storeBeforeFirst503 bool
	problems            []string
}

func newReplayRouterDouble() *replayRouterDouble {
	return &replayRouterDouble{
		records:           make(map[string]replayAuthorizationRecord),
		authorizeAttempts: make(map[string]int),
		authorizeNonces:   make(map[string][]string),
	}
}

func (r *replayRouterDouble) client() *trustedrouter.Client {
	return trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{
		Transport: roundTripFunc(r.roundTrip),
	})
}

func (r *replayRouterDouble) roundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case "/internal/gateway/authorize":
		return r.authorize(request)
	case "/internal/gateway/settle":
		r.mu.Lock()
		r.settlements++
		r.mu.Unlock()
		return replayHTTPResponse(request, http.StatusOK, `{"data":{"settled":true,"generation_id":"gen-replay","cost_microdollars":1,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`), nil
	default:
		return replayHTTPResponse(request, http.StatusNotFound, `{"error":{"message":"not found"}}`), nil
	}
}

func (r *replayRouterDouble) authorize(request *http.Request) (*http.Response, error) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		return nil, err
	}
	key, _ := body["idempotency_key"].(string)
	nonce, _ := body["invocation_nonce"].(string)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorizeAttempts[key]++
	attempt := r.authorizeAttempts[key]
	r.authorizeNonces[key] = append(r.authorizeNonces[key], nonce)
	if key == "" {
		r.problems = append(r.problems, "authorize omitted idempotency_key")
	}
	decodedNonce, decodeErr := hex.DecodeString(nonce)
	if decodeErr != nil || len(decodedNonce) != 16 {
		r.problems = append(r.problems, fmt.Sprintf("invocation_nonce %q is not 32 hex characters", nonce))
	}
	if nonce == replayCallerNonce {
		r.problems = append(r.problems, "authorize trusted the caller's invocation_nonce")
	}

	record, exists := r.records[key]
	if attempt == 1 && r.firstAttempt503 {
		if !exists && r.storeBeforeFirst503 {
			record = replayAuthorizationRecord{authorizationID: "auth-" + key, nonce: nonce}
			r.records[key] = record
		}
		return replayHTTPResponse(request, http.StatusServiceUnavailable, `{"error":{"message":"temporarily unavailable","type":"server_error"}}`), nil
	}
	if !exists {
		record = replayAuthorizationRecord{authorizationID: "auth-" + key, nonce: nonce}
		r.records[key] = record
	}
	bodyJSON, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"authorization_id":  record.authorizationID,
			"idempotent_replay": exists,
			"invocation_nonce":  record.nonce,
			"workspace_id":      "ws-replay",
			"api_key_hash":      "key-replay",
			"model":             "openai/gpt-4o-mini",
			"endpoint_id":       "openai/gpt-4o-mini@openai/prepaid",
			"provider":          "openai",
			"usage_type":        "Credits",
			"limit_usage_type":  "Credits",
			"route_candidates":  []any{},
		},
	})
	if err != nil {
		return nil, err
	}
	return replayHTTPResponse(request, http.StatusOK, string(bodyJSON)), nil
}

func replayHTTPResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func (r *replayRouterDouble) snapshot(key string) (attempts, settlements int, nonces []string, problems []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authorizeAttempts[key], r.settlements,
		append([]string(nil), r.authorizeNonces[key]...), append([]string(nil), r.problems...)
}

type replayCountingProvider struct {
	dispatches atomic.Int32
}

func (p *replayCountingProvider) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	p.dispatches.Add(1)
	_, err := io.WriteString(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_replay","type":"message","role":"assistant","content":[],"model":"test","stop_reason":null,"usage":{"input_tokens":1,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}

type replayPublicResponse struct {
	status int
	body   []byte
	err    error
}

func runReplayPublicRequest(gateway *trustedrouter.Client, provider llm.Client, key string) replayPublicResponse {
	raw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer replay-bearer\r\nIdempotency-Key: %s\r\nX-Invocation-Nonce: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		key, replayCallerNonce, len(replayTestRequestBody), replayTestRequestBody,
	)
	conn := newScriptedConn(raw, nil)
	serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, gateway, nil)
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.writes.Bytes())), nil)
	if err != nil {
		return replayPublicResponse{err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return replayPublicResponse{status: response.StatusCode, body: body, err: err}
}

func assertReplayConflict(t *testing.T, response replayPublicResponse) {
	t.Helper()
	if response.err != nil {
		t.Fatalf("request failed: %v", response.err)
	}
	if response.status != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", response.status, response.body)
	}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.body, &envelope); err != nil {
		t.Fatalf("decode 409 body: %v; body=%s", err, response.body)
	}
	if envelope.Error.Type != "idempotency_replay" || envelope.Error.Code != "idempotency_replay" ||
		!strings.Contains(strings.ToLower(envelope.Error.Message), "idempotency key") ||
		!strings.Contains(strings.ToLower(envelope.Error.Message), "used") {
		t.Fatalf("409 body = %s", response.body)
	}
}

func assertNoReplayRouterProblems(t *testing.T, problems []string) {
	t.Helper()
	if len(problems) != 0 {
		t.Fatalf("router observations: %v", problems)
	}
}

func TestPublicIdempotencyReplayGuard(t *testing.T) {
	t.Run("sequential requests dispatch and settle once", func(t *testing.T) {
		router := newReplayRouterDouble()
		provider := &replayCountingProvider{}
		first := runReplayPublicRequest(router.client(), provider, "sequential-key")
		second := runReplayPublicRequest(router.client(), provider, "sequential-key")
		if first.err != nil || first.status != http.StatusOK {
			t.Fatalf("first response status=%d err=%v body=%s", first.status, first.err, first.body)
		}
		assertReplayConflict(t, second)
		attempts, settlements, nonces, problems := router.snapshot("sequential-key")
		assertNoReplayRouterProblems(t, problems)
		if attempts != 2 || provider.dispatches.Load() != 1 || settlements != 1 {
			t.Fatalf("authorize/dispatch/settle = %d/%d/%d, want 2/1/1", attempts, provider.dispatches.Load(), settlements)
		}
		if len(nonces) != 2 || nonces[0] == nonces[1] {
			t.Fatalf("public invocation nonces = %q, want distinct values", nonces)
		}
	})

	t.Run("concurrent requests dispatch once", func(t *testing.T) {
		const requestCount = 12
		router := newReplayRouterDouble()
		provider := &replayCountingProvider{}
		responses := make(chan replayPublicResponse, requestCount)
		var workers sync.WaitGroup
		for range requestCount {
			workers.Add(1)
			go func() {
				defer workers.Done()
				responses <- runReplayPublicRequest(router.client(), provider, "concurrent-key")
			}()
		}
		workers.Wait()
		close(responses)
		successes := 0
		conflicts := 0
		for response := range responses {
			if response.status == http.StatusOK && response.err == nil {
				successes++
				continue
			}
			assertReplayConflict(t, response)
			conflicts++
		}
		attempts, settlements, nonces, problems := router.snapshot("concurrent-key")
		assertNoReplayRouterProblems(t, problems)
		uniqueNonces := make(map[string]struct{}, len(nonces))
		for _, nonce := range nonces {
			uniqueNonces[nonce] = struct{}{}
		}
		if successes != 1 || conflicts != requestCount-1 || attempts != requestCount ||
			provider.dispatches.Load() != 1 || settlements != 1 || len(uniqueNonces) != requestCount {
			t.Fatalf("success/conflict/authorize/dispatch/settle/nonce = %d/%d/%d/%d/%d/%d, want 1/%d/%d/1/1/%d",
				successes, conflicts, attempts, provider.dispatches.Load(), settlements, len(uniqueNonces),
				requestCount-1, requestCount, requestCount)
		}
	})

	t.Run("fresh invocation retry cannot claim an existing nonce", func(t *testing.T) {
		const originalNonce = "00112233445566778899aabbccddeeff"
		router := newReplayRouterDouble()
		router.records["existing-key"] = replayAuthorizationRecord{authorizationID: "auth-existing", nonce: originalNonce}
		router.firstAttempt503 = true
		provider := &replayCountingProvider{}
		response := runReplayPublicRequest(router.client(), provider, "existing-key")
		assertReplayConflict(t, response)
		attempts, settlements, nonces, problems := router.snapshot("existing-key")
		assertNoReplayRouterProblems(t, problems)
		if attempts != 2 || len(nonces) != 2 || nonces[0] != nonces[1] || nonces[0] == originalNonce ||
			provider.dispatches.Load() != 0 || settlements != 0 {
			t.Fatalf("attempts=%d nonces=%q dispatches=%d settlements=%d", attempts, nonces, provider.dispatches.Load(), settlements)
		}
	})

	t.Run("enclave retry may claim its own stored nonce once", func(t *testing.T) {
		router := newReplayRouterDouble()
		router.firstAttempt503 = true
		router.storeBeforeFirst503 = true
		provider := &replayCountingProvider{}
		response := runReplayPublicRequest(router.client(), provider, "new-retry-key")
		if response.err != nil || response.status != http.StatusOK {
			t.Fatalf("response status=%d err=%v body=%s", response.status, response.err, response.body)
		}
		attempts, settlements, nonces, problems := router.snapshot("new-retry-key")
		assertNoReplayRouterProblems(t, problems)
		if attempts != 2 || len(nonces) != 2 || nonces[0] != nonces[1] ||
			provider.dispatches.Load() != 1 || settlements != 1 {
			t.Fatalf("attempts=%d nonces=%q dispatches=%d settlements=%d", attempts, nonces, provider.dispatches.Load(), settlements)
		}
	})

	t.Run("older router replay without nonce conflicts", func(t *testing.T) {
		router := newReplayRouterDouble()
		router.records["old-router-key"] = replayAuthorizationRecord{authorizationID: "auth-old"}
		provider := &replayCountingProvider{}
		response := runReplayPublicRequest(router.client(), provider, "old-router-key")
		assertReplayConflict(t, response)
		attempts, settlements, _, problems := router.snapshot("old-router-key")
		assertNoReplayRouterProblems(t, problems)
		if attempts != 1 || provider.dispatches.Load() != 0 || settlements != 0 {
			t.Fatalf("authorize/dispatch/settle = %d/%d/%d, want 1/0/0", attempts, provider.dispatches.Load(), settlements)
		}
	})
}
