package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamcert"
)

func enableReceiptEmissionForTest(t *testing.T) []byte {
	t.Helper()
	resetReceiptTestState(t)
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	document := []byte("receipt-emission-key-binding-attestation")
	receiptSigner = signer
	receiptIssuer = "https://api.test.invalid"
	receiptAttestationCache.Store(&cachedReceiptAttestation{document: document, kind: attestation.Kind})
	return document
}

func TestReadRequestInferenceReceiptValidationAndDisabledIgnore(t *testing.T) {
	enableReceiptEmissionForTest(t)
	for _, value := range []string{"", "bad!", strings.Repeat("a", 89), "has space"} {
		t.Run(fmt.Sprintf("invalid_%d", len(value)), func(t *testing.T) {
			raw := "POST /v1/chat/completions HTTP/1.1\r\nx-inference-receipt: " + value + "\r\nContent-Length: 0\r\n\r\n"
			_, _, _, _, _, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
			if !strings.Contains(fmt.Sprint(err), "invalid x-inference-receipt") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	badConn := newScriptedConn("POST /v1/chat/completions HTTP/1.1\r\nx-inference-receipt: bad!\r\nContent-Length: 0\r\n\r\n", nil)
	serveOne(context.Background(), badConn, registryForBearer("unused"), &fakeStreamingLLM{}, nil, nil, nil, nil)
	badResponse, badBody := readRawHTTPResponse(t, badConn.writes.Bytes())
	if badResponse.StatusCode != http.StatusBadRequest || !bytes.Contains(badBody, []byte(`"error"`)) {
		t.Fatalf("bad receipt header status=%d body=%s", badResponse.StatusCode, badBody)
	}
	for _, value := range []string{"true", "n", "nonce_123-XYZ", strings.Repeat("a", 88)} {
		raw := "POST /v1/chat/completions HTTP/1.1\r\nx-inference-receipt: " + value + "\r\nContent-Length: 0\r\n\r\n"
		_, _, _, _, attribution, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil || attribution.InferenceReceipt != value {
			t.Fatalf("value %q: attribution=%q err=%v", value, attribution.InferenceReceipt, err)
		}
	}

	receiptSigner = nil
	raw := "POST /v1/chat/completions HTTP/1.1\r\nx-inference-receipt: invalid!\r\nContent-Length: 0\r\n\r\n"
	_, _, _, _, attribution, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil || attribution.InferenceReceipt != "" {
		t.Fatalf("disabled receipt header was not ignored: attribution=%q err=%v", attribution.InferenceReceipt, err)
	}
}

func TestNonStreamingReceiptCarriesProviderVerification(t *testing.T) {
	enableReceiptEmissionForTest(t)
	verifiedAt := time.Unix(1_788_000_000, 0)
	expiresAt := verifiedAt.Add(5 * time.Minute)
	provider := &verificationReceiptLLM{
		delegate:   &fakeStreamingLLM{},
		policy:     "chutes-tdx-nvidia-e2e-v1",
		verifiedAt: verifiedAt,
		expiresAt:  expiresAt,
	}
	body := []byte(`{"model":"requested-model","messages":[{"role":"user","content":"verified"}]}`)
	raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nx-inference-receipt: true\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn := newScriptedConn(raw, nil)
	serveOne(context.Background(), conn, registryForBearer("receipt-key"), provider, nil, nil, nil, nil)
	resp, _ := readRawHTTPResponse(t, conn.writes.Bytes())
	claims := decodeReceiptClaims(t, []byte(resp.Header.Get("x-inference-receipt")))
	if claims.Upstream.Tier != "tee-verified" || claims.Upstream.Policy != provider.policy || claims.Upstream.VerifiedAt != verifiedAt.Unix() || claims.Upstream.VerificationExpiresAt != expiresAt.Unix() {
		t.Fatalf("upstream claims=%+v", claims.Upstream)
	}
}

func TestReceiptClaimsCarryCertainWebPKICertAndOmitItForTEE(t *testing.T) {
	leafDER := []byte("serving-leaf-der")
	digest := sha256.Sum256(leafDER)
	wantFingerprint := base64.RawURLEncoding.EncodeToString(digest[:])

	buildClaims := func(t *testing.T, ctx context.Context) receipt.Claims {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		registry := &upstreamcert.Registry{}
		registry.Record(clientConn, leafDER)
		transport := &upstreamcert.Transport{
			Registry: registry,
			Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(req.Context())
				trace.GotConn(httptrace.GotConnInfo{Conn: clientConn})
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
			}),
		}
		upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://provider.invalid", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(upstreamReq)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		_ = response.Body.Close()
		return receiptClaims(
			ctx,
			&types.OpenAIChatRequest{Model: "requested"},
			"chat.completions",
			"response-id",
			"",
			"requested",
			newSelectedRouteTracker(),
			nil,
			sha256.Sum256(nil),
			"body",
			nil,
			nil,
		)
	}

	tlsContext := llm.WithUpstreamVerification(context.Background(), "", time.Time{}, time.Time{})
	tlsClaims := buildClaims(t, tlsContext)
	if tlsClaims.Upstream.Tier != "tls-webpki" || tlsClaims.Upstream.CertSHA256 != wantFingerprint {
		t.Fatalf("tls upstream = %+v, want fingerprint %q", tlsClaims.Upstream, wantFingerprint)
	}
	_ = llm.WithUpstreamVerification(tlsContext, "", time.Time{}, time.Time{})
	if fingerprint, ok := llm.UpstreamCertSHA256FromContext(tlsContext); ok {
		t.Fatalf("fallback reset retained cert_sha256 %q", fingerprint)
	}

	verifiedAt := time.Unix(1_788_000_000, 0)
	teeContext := llm.WithUpstreamVerification(context.Background(), "test-tee-policy", verifiedAt, verifiedAt.Add(time.Minute))
	teeClaims := buildClaims(t, teeContext)
	if teeClaims.Upstream.Tier != "tee-verified" || teeClaims.Upstream.CertSHA256 != "" {
		t.Fatalf("tee upstream must omit cert_sha256: %+v", teeClaims.Upstream)
	}
}

func TestNonStreamingReceiptChatAndResponsesExactHashes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		path  string
		route string
		body  []byte
	}{
		{"chat", "/v1/chat/completions", "chat.completions", []byte(`{"model":"requested-model","messages":[{"role":"user","content":"exact prompt"}]}`)},
		{"responses", "/v1/responses", "responses", []byte(`{"model":"requested-model","input":"exact prompt"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := enableReceiptEmissionForTest(t)
			streamer := &fakeStreamingLLM{}
			raw := fmt.Sprintf(
				"POST %s HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nx-inference-receipt: nonce_123\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				tc.path, len(tc.body), tc.body,
			)
			conn := newScriptedConn(raw, nil)
			serveOne(context.Background(), conn, registryForBearer("receipt-key"), streamer, nil, nil, nil, nil)
			resp, responseBody := readRawHTTPResponse(t, conn.writes.Bytes())
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
			}
			serialized := resp.Header.Get("x-inference-receipt")
			if serialized == "" {
				t.Fatal("missing x-inference-receipt")
			}
			if err := receipt.Verify([]byte(serialized)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			claims := decodeReceiptClaims(t, []byte(serialized))
			assertReceiptHash(t, claims.Request.Hash, tc.body)
			assertReceiptHash(t, claims.Response.Hash, responseBody)
			attDigest := sha256.Sum256(document)
			if claims.AttSHA256 != base64.RawURLEncoding.EncodeToString(attDigest[:]) {
				t.Fatalf("att_sha256=%q", claims.AttSHA256)
			}
			if claims.Route != tc.route || claims.Nonce != "nonce_123" || claims.Generation != "" || claims.Model.Requested != "requested-model" {
				t.Fatalf("claims=%+v", claims)
			}
			if claims.Upstream.Tier != "tls-webpki" || claims.Upstream.Policy != "" {
				t.Fatalf("upstream=%+v", claims.Upstream)
			}
			marshaled, err := json.Marshal(streamer.request)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(marshaled, []byte("nonce_123")) || bytes.Contains(marshaled, []byte("InferenceReceipt")) {
				t.Fatalf("receipt header leaked into provider JSON: %s", marshaled)
			}
		})
	}
}

func TestStreamingReceiptIsLastAndHashesPostBatchingWireEvents(t *testing.T) {
	enableReceiptEmissionForTest(t)
	t.Setenv("TR_SSE_BATCH_MS", "60000")
	body := []byte(`{"model":"requested-model","messages":[{"role":"user","content":"stream me"}],"stream":true}`)
	raw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nx-inference-receipt: true\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)
	conn := newScriptedConn(raw, nil)
	serveOne(context.Background(), conn, registryForBearer("receipt-key"), coalescingReceiptLLM{}, nil, nil, nil, nil)
	resp, streamBody := readRawHTTPResponse(t, conn.writes.Bytes())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, streamBody)
	}
	serialized, receiptIndex, events := capturedStreamingReceipt(t, streamBody)
	if receiptIndex != len(events)-2 || !events[len(events)-1].done {
		t.Fatalf("receipt index=%d events=%d; receipt must immediately precede DONE", receiptIndex, len(events))
	}
	if err := receipt.Verify(serialized); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	claims := decodeReceiptClaims(t, serialized)
	digest, count := recomputeCapturedSSEHash(t, events[:receiptIndex], "sse-data-v1")
	if claims.Response.Hash != base64.RawURLEncoding.EncodeToString(digest[:]) || claims.Response.Events == nil || *claims.Response.Events != count {
		t.Fatalf("response claims=%+v count=%d", claims.Response, count)
	}
	if claims.Response.Of != "sse-data-v1" || claims.AttSHA256 != "" || claims.Generation != "" {
		t.Fatalf("stream claims=%+v", claims)
	}
	if !bytes.Contains(streamBody, []byte(`"content":" world!"`)) {
		t.Fatalf("TR_SSE_BATCH_MS did not coalesce captured wire payloads: %s", streamBody)
	}

	mutated := append([]byte(nil), events[1].payload...)
	mutated[len(mutated)/2] ^= 1
	mutatedEvents := append([]capturedSSEEvent(nil), events[:receiptIndex]...)
	mutatedEvents[1].payload = mutated
	mutatedDigest, _ := recomputeCapturedSSEHash(t, mutatedEvents, "sse-data-v1")
	if base64.RawURLEncoding.EncodeToString(mutatedDigest[:]) == claims.Response.Hash {
		t.Fatal("flipping one captured payload byte did not invalidate the receipt hash")
	}
}

func TestResponsesStreamingReceiptUsesNamedEventDomain(t *testing.T) {
	enableReceiptEmissionForTest(t)
	body := []byte(`{"model":"requested-model","input":"stream me","stream":true}`)
	raw := fmt.Sprintf(
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nx-inference-receipt: response_nonce\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)
	conn := newScriptedConn(raw, nil)
	serveOne(context.Background(), conn, registryForBearer("receipt-key"), &fakeStreamingLLM{}, nil, nil, nil, nil)
	_, streamBody := readRawHTTPResponse(t, conn.writes.Bytes())
	serialized, receiptIndex, events := capturedStreamingReceipt(t, streamBody)
	claims := decodeReceiptClaims(t, serialized)
	digest, count := recomputeCapturedSSEHash(t, events[:receiptIndex], "sse-events-v1")
	if claims.Route != "responses" || claims.Response.Of != "sse-events-v1" || claims.Response.Hash != base64.RawURLEncoding.EncodeToString(digest[:]) || claims.Response.Events == nil || *claims.Response.Events != count {
		t.Fatalf("claims=%+v count=%d", claims, count)
	}
	if receiptIndex != len(events)-2 || len(events[receiptIndex].name) != 0 {
		t.Fatalf("responses receipt is not the final unnamed event: %#v", events[receiptIndex])
	}
}

func TestTruncatedStreamingResponseGetsNoReceipt(t *testing.T) {
	enableReceiptEmissionForTest(t)
	body := []byte(`{"model":"requested-model","messages":[{"role":"user","content":"stream me"}],"stream":true}`)
	raw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nx-inference-receipt: true\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)
	conn := newScriptedConn(raw, nil)
	serveOne(context.Background(), conn, registryForBearer("receipt-key"), truncatedReceiptLLM{}, nil, nil, nil, nil)
	_, streamBody := readRawHTTPResponse(t, conn.writes.Bytes())
	if bytes.Contains(streamBody, []byte("inference_receipt")) {
		t.Fatalf("truncated stream carried a receipt: %s", streamBody)
	}
}

type truncatedReceiptLLM struct{}
type coalescingReceiptLLM struct{}

func (coalescingReceiptLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, err := io.WriteString(out, `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":2,"output_tokens":3}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}

type verificationReceiptLLM struct {
	delegate   llm.Client
	policy     string
	verifiedAt time.Time
	expiresAt  time.Time
}

func (v *verificationReceiptLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	_ = llm.WithUpstreamVerification(ctx, v.policy, v.verifiedAt, v.expiresAt)
	return v.delegate.InvokeStreaming(ctx, req, body, out, options...)
}

func (truncatedReceiptLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, err := io.WriteString(out, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n")
	return err
}

type capturedSSEEvent struct {
	name    []byte
	payload []byte
	done    bool
}

func capturedStreamingReceipt(t *testing.T, stream []byte) ([]byte, int, []capturedSSEEvent) {
	t.Helper()
	events := make([]capturedSSEEvent, 0)
	receiptIndex := -1
	var serialized []byte
	for len(stream) > 0 {
		raw, rest, ok := nextSSEEvent(stream)
		if !ok {
			t.Fatalf("incomplete SSE tail: %q", stream)
		}
		stream = rest
		name, payload, done, valid := receiptSSEEvent(raw)
		if !valid {
			t.Fatalf("invalid emitted SSE event: %q", raw)
		}
		events = append(events, capturedSSEEvent{append([]byte(nil), name...), append([]byte(nil), payload...), done})
		var object map[string]json.RawMessage
		if !done && json.Unmarshal(payload, &object) == nil {
			if receiptJSON, ok := object["inference_receipt"]; ok {
				receiptIndex = len(events) - 1
				serialized = append([]byte(nil), receiptJSON...)
			}
		}
	}
	if receiptIndex < 0 || len(serialized) == 0 {
		t.Fatalf("stream has no receipt event: %#v", events)
	}
	return serialized, receiptIndex, events
}

func recomputeCapturedSSEHash(t *testing.T, events []capturedSSEEvent, domain string) ([32]byte, int) {
	t.Helper()
	var preimage bytes.Buffer
	count := 0
	for _, event := range events {
		if event.done {
			continue
		}
		count++
		if domain == "sse-events-v1" {
			preimage.Write(event.name)
			preimage.WriteByte('\n')
		} else if len(event.name) != 0 {
			t.Fatalf("named event in sse-data-v1: %q", event.name)
		}
		preimage.Write(event.payload)
		preimage.WriteByte('\n')
	}
	return sha256.Sum256(preimage.Bytes()), count
}

func decodeReceiptClaims(t *testing.T, serialized []byte) receipt.Claims {
	t.Helper()
	trimmed := bytes.TrimSpace(serialized)
	payload := ""
	if bytes.HasPrefix(trimmed, []byte{'{'}) {
		var flattened struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(trimmed, &flattened); err != nil {
			t.Fatalf("decode flattened JWS: %v", err)
		}
		payload = flattened.Payload
	} else {
		parts := strings.Split(string(trimmed), ".")
		if len(parts) != 3 {
			t.Fatalf("compact JWS parts=%d", len(parts))
		}
		payload = parts[1]
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims receipt.Claims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func assertReceiptHash(t *testing.T, encoded string, raw []byte) {
	t.Helper()
	digest := sha256.Sum256(raw)
	if encoded != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("hash=%q want=%q", encoded, base64.RawURLEncoding.EncodeToString(digest[:]))
	}
}

func TestOptOutRequestsCarryNoReceiptArtifacts(t *testing.T) {
	// The receipt surface must be invisible unless requested: no extra
	// response header on the buffered path, no extra SSE event on the
	// streaming path, even with the signer live and an attestation cached.
	enableReceiptEmissionForTest(t)
	body := []byte(`{"model":"requested-model","messages":[{"role":"user","content":"plain"}]}`)
	raw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)
	conn := newScriptedConn(raw, nil)
	serveOne(context.Background(), conn, registryForBearer("receipt-key"), &fakeStreamingLLM{}, nil, nil, nil, nil)
	resp, respBody := readRawHTTPResponse(t, conn.writes.Bytes())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, respBody)
	}
	if got := resp.Header.Get("x-inference-receipt"); got != "" {
		t.Fatalf("opt-out response carried x-inference-receipt: %q", got)
	}

	streamBody := []byte(`{"model":"requested-model","messages":[{"role":"user","content":"plain"}],"stream":true}`)
	streamRaw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer receipt-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(streamBody), streamBody,
	)
	streamConn := newScriptedConn(streamRaw, nil)
	serveOne(context.Background(), streamConn, registryForBearer("receipt-key"), &fakeStreamingLLM{}, nil, nil, nil, nil)
	_, streamOut := readRawHTTPResponse(t, streamConn.writes.Bytes())
	if bytes.Contains(streamOut, []byte("inference_receipt")) {
		t.Fatalf("opt-out stream carried a receipt event: %s", streamOut)
	}
	if !bytes.Contains(streamOut, []byte("data: [DONE]")) {
		t.Fatalf("opt-out stream did not terminate normally: %s", streamOut)
	}
}

type tierLaunderingLLM struct {
	attempts   int
	verifiedAt time.Time
	expiresAt  time.Time
}

func (f *tierLaunderingLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	f.attempts++
	if f.attempts == 1 {
		// An attested candidate verifies its upstream, fills the carrier,
		// and THEN fails before serving bytes.
		_ = llm.WithUpstreamVerification(ctx, "chutes-tdx-nvidia-e2e-v1", f.verifiedAt, f.expiresAt)
		return fmt.Errorf("llm/upstream: http 429: rate limited")
	}
	return (&fakeStreamingLLM{}).InvokeStreaming(ctx, req, body, out, options...)
}

func TestFailedVerifiedCandidateDoesNotLendTierToFallbackReceipt(t *testing.T) {
	// The receipt for a response actually served by a plain-TLS fallback must
	// claim tls-webpki even when an earlier attested candidate verified and
	// failed: provider_stream clears the carrier before every attempt.
	enableReceiptEmissionForTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_auto","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[{"model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits"},{"model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_tier","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	trGateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	verifiedAt := time.Unix(1_788_000_000, 0)
	streamer := &tierLaunderingLLM{verifiedAt: verifiedAt, expiresAt: verifiedAt.Add(5 * time.Minute)}
	serverConn, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)
	requestBody := []byte(`{"model":"trustedrouter/auto","stream":false,"messages":[{"role":"user","content":"tier check"}],"max_tokens":32}`)
	_, err := fmt.Fprintf(client,
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer tier-bearer\r\nx-inference-receipt: true\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody), requestBody)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if streamer.attempts != 2 {
		t.Fatalf("attempts = %d, want verified-failure then fallback", streamer.attempts)
	}
	serialized := resp.Header.Get("x-inference-receipt")
	if serialized == "" {
		t.Fatal("missing x-inference-receipt on fallback response")
	}
	claims := decodeReceiptClaims(t, []byte(serialized))
	if claims.Upstream.Tier != "tls-webpki" || claims.Upstream.Policy != "" || claims.Upstream.VerifiedAt != 0 {
		t.Fatalf("fallback receipt laundered verification tier: %+v", claims.Upstream)
	}
}
