package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const testRequestLogID = "rlog_0123456789abcdef0123456789abcdef"

func TestResponseStatsConnInjectsRequestIDOnFirstWrite(t *testing.T) {
	first := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	second := []byte("second-write")
	headers := []byte("x-request-id: " + testRequestLogID + "\r\nrequest-id: " + testRequestLogID + "\r\n")
	statusLineEnd := bytes.Index(first, []byte("\r\n")) + len("\r\n")
	want := append([]byte{}, first[:statusLineEnd]...)
	want = append(want, headers...)
	want = append(want, first[statusLineEnd:]...)
	want = append(want, second...)

	server, peer := net.Pipe()
	stats := &responseStatsConn{Conn: server}
	stats.BeginRequest(testRequestLogID)
	type writeResults struct {
		firstN    int
		firstErr  error
		secondN   int
		secondErr error
	}
	resultCh := make(chan writeResults, 1)
	go func() {
		firstN, firstErr := stats.Write(first)
		secondN, secondErr := stats.Write(second)
		_ = stats.Close()
		resultCh <- writeResults{firstN: firstN, firstErr: firstErr, secondN: secondN, secondErr: secondErr}
	}()

	got, err := io.ReadAll(peer)
	if err != nil {
		t.Fatalf("read peer: %v", err)
	}
	_ = peer.Close()
	result := <-resultCh
	if result.firstErr != nil || result.secondErr != nil {
		t.Fatalf("write errors = (%v, %v)", result.firstErr, result.secondErr)
	}
	if result.firstN != len(first) || result.secondN != len(second) {
		t.Fatalf("caller byte counts = (%d, %d), want (%d, %d)", result.firstN, result.secondN, len(first), len(second))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("peer bytes:\n got: %q\nwant: %q", got, want)
	}
	status, responseBytes := stats.Snapshot()
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	// responseBytes is a wire count, so it deliberately includes both injected
	// request-ID headers even though Write returned only the caller's byte count.
	if responseBytes != len(want) {
		t.Fatalf("response bytes = %d, want wire length %d", responseBytes, len(want))
	}
}

func TestResponseStatsConnRequestIDFramingSafety(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
		writes    [][]byte
	}{
		{
			name:      "split status line",
			requestID: testRequestLogID,
			writes: [][]byte{
				[]byte("HTTP/1.1 200 OK"),
				[]byte("\r\nContent-Length: 0\r\n\r\n"),
			},
		},
		{
			name:      "non HTTP first write",
			requestID: testRequestLogID,
			writes: [][]byte{
				[]byte("not an HTTP response"),
				[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			},
		},
		{
			name:      "empty request ID",
			requestID: "",
			writes: [][]byte{
				[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, peer := net.Pipe()
			stats := &responseStatsConn{Conn: server}
			stats.BeginRequest(test.requestID)
			errCh := make(chan error, 1)
			go func() {
				for _, write := range test.writes {
					n, err := stats.Write(write)
					if err != nil {
						errCh <- err
						_ = stats.Close()
						return
					}
					if n != len(write) {
						errCh <- fmt.Errorf("write count = %d, want %d", n, len(write))
						_ = stats.Close()
						return
					}
				}
				errCh <- stats.Close()
			}()

			got, err := io.ReadAll(peer)
			if err != nil {
				t.Fatalf("read peer: %v", err)
			}
			_ = peer.Close()
			if err := <-errCh; err != nil {
				t.Fatalf("write response: %v", err)
			}
			want := bytes.Join(test.writes, nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("peer bytes:\n got: %q\nwant: %q", got, want)
			}
			if bytes.Contains(got, []byte("request-id:")) {
				t.Fatalf("unsafe request ID injection: %q", got)
			}
		})
	}
}

func TestResponseStatsConnResetSnapshotClearsRequestID(t *testing.T) {
	server, peer := net.Pipe()
	stats := &responseStatsConn{Conn: server}
	stats.BeginRequest(testRequestLogID)
	stats.ResetSnapshot()
	raw := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	errCh := make(chan error, 1)
	go func() {
		_, err := stats.Write(raw)
		_ = stats.Close()
		errCh <- err
	}()
	got, err := io.ReadAll(peer)
	if err != nil {
		t.Fatalf("read peer: %v", err)
	}
	_ = peer.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("write response: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("peer bytes = %q, want %q", got, raw)
	}
}

func TestResponseWriterFamiliesInjectRequestID(t *testing.T) {
	oldGetAttestation := getAttestation
	getAttestation = func(_, _, _, _ []byte) ([]byte, error) {
		return []byte{0xa1, 0x61, 0x61, 0x01}, nil
	}
	t.Cleanup(func() { getAttestation = oldGetAttestation })

	tests := []struct {
		name       string
		write      func(io.Writer) error
		wantStatus int
		wantHeader map[string]string
		wantBody   string
	}{
		{
			name: "writeError 413",
			write: func(w io.Writer) error {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return nil
			},
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name: "writeError 431",
			write: func(w io.Writer) error {
				writeError(w, http.StatusRequestHeaderFieldsTooLarge, "request headers too large")
				return nil
			},
			wantStatus: http.StatusRequestHeaderFieldsTooLarge,
		},
		{
			name: "writeError 401",
			write: func(w io.Writer) error {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return nil
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "writeErrorWithSourceHeaders",
			write: func(w io.Writer) error {
				writeErrorWithSourceHeaders(w, http.StatusTooManyRequests, "slow down", "router", map[string]string{
					"Retry-After":     "30",
					shouldRetryHeader: "true",
				})
				return nil
			},
			wantStatus: http.StatusTooManyRequests,
			wantHeader: map[string]string{"Retry-After": "30", shouldRetryHeader: "true"},
		},
		{
			name: "writeJSONResponse",
			write: func(w io.Writer) error {
				writeJSONResponse(w, http.StatusOK, []byte(`{"ok":true}`))
				return nil
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"ok":true}`,
		},
		{
			name: "writeResponseHead chunked",
			write: func(w io.Writer) error {
				if err := writeResponseHead(w, http.StatusOK, "text/event-stream"); err != nil {
					return err
				}
				chunked := newChunkedWriter(w)
				if _, err := chunked.Write([]byte("data: done\n\n")); err != nil {
					return err
				}
				return chunked.Close()
			},
			wantStatus: http.StatusOK,
			wantBody:   "data: done\n\n",
		},
		{
			name: "attestation CBOR",
			write: func(w io.Writer) error {
				if !serveAttestation(w, []byte("leaf"), []byte("device"), nil, []byte("binding")) {
					return fmt.Errorf("serveAttestation returned false")
				}
				return nil
			},
			wantStatus: http.StatusOK,
			wantHeader: map[string]string{"Content-Type": "application/cbor"},
		},
		{
			name: "user model raw error writer",
			write: func(w io.Writer) error {
				writeUserModelBufferedErrorWithHeaders(w, "chat.completions", &userModelDispatchError{
					callerStatus: http.StatusBadGateway,
					message:      "user model failed",
					refundStatus: http.StatusBadGateway,
					refundType:   "provider_error",
				}, map[string]string{shouldRetryHeader: "false"})
				return nil
			},
			wantStatus: http.StatusBadGateway,
			wantHeader: map[string]string{shouldRetryHeader: "false"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, body := responseFromStatsConn(t, testRequestLogID, test.write)
			if resp.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, test.wantStatus)
			}
			requireRequestIDHeaders(t, resp, testRequestLogID)
			for name, want := range test.wantHeader {
				if got := resp.Header.Get(name); got != want {
					t.Fatalf("%s = %q, want %q", name, got, want)
				}
			}
			if test.wantBody != "" && string(body) != test.wantBody {
				t.Fatalf("body = %q, want %q", body, test.wantBody)
			}
		})
	}
}

func TestWriteHealthResponseInjectsDifferentRequestIDsOnKeepAlive(t *testing.T) {
	requestIDs := []string{
		"rlog_11111111111111111111111111111111",
		"rlog_22222222222222222222222222222222",
	}
	server, peer := net.Pipe()
	stats := &responseStatsConn{Conn: server}
	errCh := make(chan error, 1)
	go func() {
		for _, requestID := range requestIDs {
			stats.BeginRequest(requestID)
			writeHealthResponse(stats, true, time.Now())
		}
		errCh <- stats.Close()
	}()

	reader := bufio.NewReader(peer)
	for i, requestID := range requestIDs {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("read health response %d: %v", i+1, err)
		}
		requireRequestIDHeaders(t, resp, requestID)
		if resp.Header.Get("Connection") != "keep-alive" {
			t.Fatalf("response %d Connection = %q, want keep-alive", i+1, resp.Header.Get("Connection"))
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatalf("read health body %d: %v", i+1, err)
		}
		_ = resp.Body.Close()
	}
	_ = peer.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("write health responses: %v", err)
	}
}

func TestServeOneUsesResponseRequestIDForSettlementOnly(t *testing.T) {
	authorizePayloadCh := make(chan map[string]any, 1)
	settlePayloadCh := make(chan map[string]any, 1)
	trGateway := trustedrouter.New("https://control.example", "internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				return nil, err
			}
			var body string
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				authorizePayloadCh <- payload
				body = `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
			case "/internal/gateway/settle":
				settlePayloadCh <- payload
				body = `{"data":{"generation_id":"gen_1","cost_microdollars":1}}`
			default:
				return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}, nil
		}),
	})

	server, peer := net.Pipe()
	defer peer.Close()
	go serveOne(context.Background(), server, auth.New(nil), &fakeStreamingLLM{}, nil, nil, trGateway, nil)
	body := []byte(`{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"hello"}],"max_tokens":8}`)
	if _, err := fmt.Fprintf(
		peer,
		"POST /v1/chat/completions HTTP/1.1\r\n"+
			"Authorization: Bearer test-key\r\n"+
			"User-Agent: OpenAI/Python 2.46.0\r\n"+
			"X-Stainless-Lang: python\r\n"+
			"X-Stainless-Runtime: CPython\r\n"+
			"X-Stainless-Runtime-Version: 3.12.1\r\n"+
			"X-Stainless-OS: MacOS\r\n"+
			"X-Stainless-Arch: arm64\r\n"+
			"X-Stainless-Retry-Count: 7\r\n"+
			"X-Stainless-Timeout: 120\r\n"+
			"X-TR-Client: v=1;a=1;po=transport_error;pc=connect_timeout;ph=apex;pm=10012;sm=10530;s=0;fo=1\r\n"+
			"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	requestID := resp.Header.Get("x-request-id")
	if !stringsMatchRequestLogID(requestID) {
		t.Fatalf("x-request-id = %q, want rlog_<32 lowercase hex>", requestID)
	}
	requireRequestIDHeaders(t, resp, requestID)
	authorizePayload := <-authorizePayloadCh
	if _, ok := authorizePayload["gateway_request_id"]; ok {
		t.Fatal("authorize body contains gateway_request_id")
	}
	if _, ok := authorizePayload["client"]; ok {
		t.Fatal("authorize body contains client")
	}
	settlePayload := <-settlePayloadCh
	if got := settlePayload["gateway_request_id"]; got != requestID {
		t.Fatalf("settle gateway_request_id = %#v, want %q", got, requestID)
	}
	wantClient := map[string]any{
		"v":                float64(1),
		"source":           "tr",
		"sdk":              "openai-python",
		"sdk_version":      "2.46.0",
		"lang":             "python",
		"runtime":          "cpython/3.12.1",
		"os":               "macos",
		"arch":             "arm64",
		"timeout_ms":       float64(120000),
		"attempt":          float64(1),
		"prev_outcome":     "transport_error",
		"prev_error_class": "connect_timeout",
		"prev_host":        "apex",
		"prev_elapsed_ms":  float64(10012),
		"since_first_ms":   float64(10530),
		"stream":           false,
		"failover_used":    true,
	}
	if got := settlePayload["client"]; !reflect.DeepEqual(got, wantClient) {
		t.Fatalf("settle client = %#v, want %#v", got, wantClient)
	}
}

func TestServeOneMalformedTRClientFallsBackToStainlessContext(t *testing.T) {
	authorizePayloadCh := make(chan map[string]any, 1)
	settlePayloadCh := make(chan map[string]any, 1)
	trGateway := trustedrouter.New("https://control.example", "internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				return nil, err
			}
			var body string
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				authorizePayloadCh <- payload
				body = `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
			case "/internal/gateway/settle":
				settlePayloadCh <- payload
				body = `{"data":{"generation_id":"gen_1","cost_microdollars":1}}`
			default:
				return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}, nil
		}),
	})

	server, peer := net.Pipe()
	defer peer.Close()
	go serveOne(context.Background(), server, auth.New(nil), &fakeStreamingLLM{}, nil, nil, trGateway, nil)
	body := []byte(`{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"hello"}],"max_tokens":8}`)
	if _, err := fmt.Fprintf(
		peer,
		"POST /v1/chat/completions HTTP/1.1\r\n"+
			"Authorization: Bearer test-key\r\n"+
			"X-Stainless-Lang: Go\r\n"+
			"X-TR-Client: v=1;zz=1\r\n"+
			"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if payload := <-authorizePayloadCh; payload["client"] != nil {
		t.Fatalf("authorize body contains client: %#v", payload)
	}
	payload := <-settlePayloadCh
	want := map[string]any{"v": float64(1), "source": "stainless", "lang": "go"}
	if !reflect.DeepEqual(payload["client"], want) {
		t.Fatalf("settle client = %#v, want %#v", payload["client"], want)
	}
}

func TestServeOneRefundCarriesClientContext(t *testing.T) {
	authorizePayloadCh := make(chan map[string]any, 1)
	refundPayloadCh := make(chan map[string]any, 1)
	trGateway := trustedrouter.New("https://control.example", "internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				return nil, err
			}
			var body string
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				authorizePayloadCh <- payload
				body = `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
			case "/internal/gateway/refund":
				refundPayloadCh <- payload
				body = `{"data":{"refunded":true}}`
			default:
				return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}, nil
		}),
	})

	server, peer := net.Pipe()
	defer peer.Close()
	go serveOne(context.Background(), server, auth.New(nil), &failingStreamingLLM{}, nil, nil, trGateway, nil)
	body := []byte(`{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"hello"}],"max_tokens":8}`)
	if _, err := fmt.Fprintf(
		peer,
		"POST /v1/chat/completions HTTP/1.1\r\n"+
			"Authorization: Bearer test-key\r\n"+
			"User-Agent: trusted-router-js/1.2.3 node/22.4.0\r\n"+
			"X-TR-Client: v=1;a=0;s=0\r\n"+
			"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if payload := <-authorizePayloadCh; payload["client"] != nil {
		t.Fatalf("authorize body contains client: %#v", payload)
	}
	payload := <-refundPayloadCh
	want := map[string]any{
		"v": float64(1), "source": "tr", "sdk": "tr-js", "sdk_version": "1.2.3",
		"runtime": "node/22.4.0", "attempt": float64(0), "stream": false,
	}
	if !reflect.DeepEqual(payload["client"], want) {
		t.Fatalf("refund client = %#v, want %#v", payload["client"], want)
	}
}

func TestServeOneEmbeddingsSettlementCarriesClientContext(t *testing.T) {
	authorizePayloadCh := make(chan map[string]any, 1)
	settlePayloadCh := make(chan map[string]any, 1)
	trGateway := trustedrouter.New("https://control.example", "internal", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				return nil, err
			}
			var body string
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				authorizePayloadCh <- payload
				body = `{"data":{"authorization_id":"auth_embeddings","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/text-embedding-3-small","endpoint_id":"openai/text-embedding-3-small@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`
			case "/internal/gateway/settle":
				settlePayloadCh <- payload
				body = `{"data":{"generation_id":"gen_embeddings","cost_microdollars":1}}`
			default:
				return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}, nil
		}),
	})

	server, peer := net.Pipe()
	defer peer.Close()
	go serveOne(context.Background(), server, auth.New(nil), &fakeEmbeddingLLM{}, nil, nil, trGateway, nil)
	body := []byte(`{"model":"openai/text-embedding-3-small","input":"hello"}`)
	if _, err := fmt.Fprintf(
		peer,
		"POST /v1/embeddings HTTP/1.1\r\n"+
			"Authorization: Bearer test-key\r\n"+
			"X-TR-Client: v=1;a=0;s=0\r\n"+
			"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if payload := <-authorizePayloadCh; payload["client"] != nil {
		t.Fatalf("embeddings authorize body contains client: %#v", payload)
	}
	payload := <-settlePayloadCh
	want := map[string]any{"v": float64(1), "source": "tr", "attempt": float64(0), "stream": false}
	if !reflect.DeepEqual(payload["client"], want) {
		t.Fatalf("embeddings settle client = %#v, want %#v", payload["client"], want)
	}
}

type fakeEmbeddingLLM struct{ fakeStreamingLLM }

func (f *fakeEmbeddingLLM) InvokeEmbedding(
	_ context.Context,
	req *types.EmbeddingRequest,
	_ ...llm.InvokeOptions,
) (*types.EmbeddingResponse, error) {
	return &types.EmbeddingResponse{
		Object: "list",
		Data: []types.EmbeddingData{{
			Object:    "embedding",
			Embedding: json.RawMessage(`[0.1,0.2]`),
			Index:     0,
		}},
		Model: req.Model,
		Usage: types.EmbeddingUsage{PromptTokens: 1, TotalTokens: 1},
	}, nil
}

func responseFromStatsConn(t *testing.T, requestID string, write func(io.Writer) error) (*http.Response, []byte) {
	t.Helper()
	server, peer := net.Pipe()
	stats := &responseStatsConn{Conn: server}
	stats.BeginRequest(requestID)
	errCh := make(chan error, 1)
	go func() {
		err := write(stats)
		closeErr := stats.Close()
		if err == nil {
			err = closeErr
		}
		errCh <- err
	}()

	resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	_ = peer.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("write response: %v", err)
	}
	return resp, body
}

func requireRequestIDHeaders(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	for _, name := range []string{"x-request-id", "request-id"} {
		if got := resp.Header.Get(name); got != want {
			t.Fatalf("%s = %q, want %q; headers=%v", name, got, want, resp.Header)
		}
	}
}

func stringsMatchRequestLogID(value string) bool {
	if len(value) != len("rlog_")+32 || value[:len("rlog_")] != "rlog_" {
		return false
	}
	for _, char := range value[len("rlog_"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}
