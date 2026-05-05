// quill-enclave runs INSIDE the Nitro Enclave.
//
// At startup it dials the parent via vsock to fetch BootstrapData (device
// list + Bedrock credentials + region + vsock-proxy port). It then listens
// on vsock CID 16 port 8001 for inbound HTTP from the parent's relay,
// validates the bearer, calls Bedrock via the vsock-tunneled HTTPS client,
// and streams OpenAI-format chunks back.
//
// Strict policy: no prompt logging. The AWS build keeps all network behind
// vsock; the GCP/OpenRouter build uses direct egress for ACME and the ZDR
// upstream. The only `fmt.Print*` calls in this binary go to stdout/stderr
// at startup for fatal-error visibility ONLY when running in --debug-mode.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/broadcast"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/entropy"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// EnclaveListenPort + newRawListener are provided by listener_aws.go
// (vsock CID-LOCAL) or listener_gcp.go (plain TCP).

const maxRequestBodyBytes = 4 * 1024 * 1024
const maxAttestationNonceBytes = 64

var errBodyTooLarge = errors.New("request body too large")

func main() {
	ctx := context.Background()

	// 0. Seed the kernel's CSPRNG from the NSM hardware RNG before any
	// crypto/rand consumer (TLS keypair, request IDs, x509 serials) reads
	// it. Linux's /dev/urandom is starved at boot inside an enclave —
	// without seeding, an early TLS keypair could be generated from
	// dangerously low entropy. NSM-sourced bytes come from the Nitro
	// hypervisor's hardware RNG, distinct from the guest kernel's pool.
	// Skipped outside enclaves (no /dev/nsm); not fatal if seeding fails
	// — the kernel will still hit a real entropy source eventually, but
	// the trust story prefers we shout if it doesn't.
	if err := entropy.Seed(); err != nil {
		fmt.Fprintf(os.Stderr, "entropy.seed_failed: %v (continuing)\n", err)
	}

	// 1. Fetch bootstrap data from parent.
	boot, err := bootstrap.Fetch(ctx)
	if err != nil {
		// Boot fatal: emit to stderr only in debug mode (--debug-mode shows console).
		fmt.Fprintf(os.Stderr, "bootstrap fetch failed: %v\n", err)
		os.Exit(1)
	}

	// 2. Build registries. Capture a canonical hash of the device list
	// so /attestation can include it in the document's UserData — clients
	// learn the exact set of bearer tokens currently authorized, and any
	// silent rotation produces a new attestation.
	registry := auth.New(boot.Devices)
	br := llm.New(boot) // build-tag-gated: AWS Bedrock by default, GCP Vertex with -tags gcp
	trGateway := trustedrouter.NewFromBootstrap(boot)
	var byokSecrets *byokcache.Cache
	if trGateway.Enabled() {
		byokSecrets = byokcache.New(byokcache.Options{
			Unwrapper: &byokcache.GoogleKMSUnwrapper{},
		})
	}

	deviceBlob, _ := json.Marshal(boot.Devices)

	// 3. Listen on vsock/TCP. When QUILL_ENCLAVE_TLS=true, wrap the listener
	// with an enclave-owned cert so TLS is terminated INSIDE the attested
	// binary — i.e. the parent never sees plaintext, and the PCR0-measured
	// code is the first thing to handle the prompt bytes.
	//
	// Phase 1: feature-flagged. The parent's relay still ships HTTP-over-
	// vsock by default; flipping the flag without flipping the parent will
	// break the chain (the parent won't speak TLS). Phase 2 swaps the
	// parent to a raw TCP pump so this flag becomes the default.
	rawListener, err := newRawListener()
	if err != nil {
		fmt.Fprintf(os.Stderr, "raw listener failed: %v\n", err)
		os.Exit(1)
	}
	var listener net.Listener = rawListener

	// tlsServer is non-nil only when TLS is enabled; the /attestation handler
	// uses it to bind the live cert into the NSM-signed document. Empty
	// = /attestation responds 503 (we have no cert to attest).
	var tlsServer *enclavetls.Server

	if os.Getenv("QUILL_ENCLAVE_TLS") == "true" {
		apiHost := getenv("QUILL_API_HOST", "api.quillrouter.com")
		mode := getenv("QUILL_TLS_MODE", "self-signed")
		var err error
		if mode == "acme" {
			tlsServer, err = enclavetls.NewACME(
				apiHost,
				os.Getenv("QUILL_ACME_EMAIL"),
				os.Getenv("QUILL_ACME_CACHE_DIR"),
				os.Getenv("QUILL_ACME_DIRECTORY_URL"),
				os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET"),
			)
		} else {
			tlsServer, err = enclavetls.NewSelfSigned(apiHost)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclavetls cert failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "enclavetls.mode=%s host=%s cert_fingerprint=%s\n", mode, apiHost, tlsServer.CurrentFingerprint())
		listener = tlsServer.Wrap(rawListener)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go serveOne(ctx, conn, registry, br, tlsServer, deviceBlob, trGateway, byokSecrets)
	}
}

func serveOne(
	ctx context.Context,
	conn net.Conn,
	reg *auth.Registry,
	br llm.Client,
	tlsServer *enclavetls.Server,
	deviceBlob []byte,
	trGateway *trustedrouter.Client,
	byokSecrets *byokcache.Cache,
) {
	defer conn.Close()

	method, path, bearer, body, err := readRequest(conn)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(conn, 413, "request body too large")
			return
		}
		writeError(conn, 400, "could not read request")
		return
	}
	routePath, nonce, err := parseRequestTarget(path)
	if err != nil {
		writeError(conn, 400, err.Error())
		return
	}

	// /attestation is the only path that's anonymous: clients call it
	// BEFORE pinning, so requiring a bearer would defeat the purpose.
	// Trust binding still holds — the doc commits to the live TLS cert,
	// which only this enclave can speak.
	if method == "GET" && routePath == "/attestation" {
		serveAttestation(conn, tlsServer, deviceBlob, nonce)
		return
	}

	trEnabled := trGateway != nil && trGateway.Enabled()
	if !trEnabled {
		device := reg.Lookup(bearer)
		if device == nil {
			writeError(conn, 401, "Invalid API key")
			return
		}
		_ = device // device_id can be reported via a counter-flush vsock RPC in V1.1
	} else if bearer == "" {
		writeError(conn, 401, "Invalid API key")
		return
	}

	var req types.OpenAIChatRequest
	routeType := "chat.completions"
	originalInput := any(nil)
	if routePath == "/v1/responses" {
		routeType = "responses"
		responsesReq, err := parseResponsesRequest(body)
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeError(conn, aerr.Status, aerr.Message)
				return
			}
			writeError(conn, 400, "invalid JSON")
			return
		}
		chatReq, err := adapter.ResponsesToChat(responsesReq)
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeError(conn, aerr.Status, aerr.Message)
				return
			}
			writeError(conn, 400, "invalid responses request")
			return
		}
		req = *chatReq
		originalInput = responsesReq.Input
	} else if routePath == "/v1/chat/completions" {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(conn, 400, "invalid JSON")
			return
		}
		originalInput = req.Messages
	} else {
		writeError(conn, 404, "route not found")
		return
	}

	anthropicReq, err := adapter.ToAnthropic(&req, "claude-opus-4-7")
	if err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeError(conn, aerr.Status, aerr.Message)
			return
		}
		writeError(conn, 500, "adapter error")
		return
	}
	var authorization *trustedrouter.Authorization
	var invokeOptions []llm.InvokeOptions
	requestStarted := time.Now()
	if trEnabled {
		authorization, err = trGateway.AuthorizeWithRoute(ctx, bearer, &req, routeType)
		if err != nil {
			writeError(conn, statusFromControlPlaneError(err), "gateway authorization failed")
			return
		}
		req.Model = authorization.Model
		req.Models = nil
		providerKey, keyErr := providerAPIKey(ctx, byokSecrets, authorization)
		if keyErr != nil {
			_ = trGateway.Refund(ctx, authorization, 502, "byok_secret_error", time.Since(requestStarted).Seconds())
			writeError(conn, 502, "BYOK provider key unavailable")
			return
		}
		// Always populate InvokeOptions so the llm Client knows which
		// upstream the control plane authorized. Multi-backend builds
		// dispatch on this field; single-backend builds ignore Provider
		// and just need ProviderAPIKey when usage_type==BYOK.
		invokeOptions = append(invokeOptions, llm.InvokeOptions{
			ProviderAPIKey: providerKey,
			Provider:       authorization.Provider,
			EndpointID:     authorization.EndpointID,
			UsageType:      authorization.UsageType,
		})
	}
	if routeType == "responses" && !req.Stream {
		serveResponsesNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput)
		return
	}
	serveStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, routeType)
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func parseResponsesRequest(body []byte) (*types.OpenAIResponsesRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if err := adapter.RejectUnsupportedResponsesFields(raw); err != nil {
		return nil, err
	}
	var req types.OpenAIResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func serveResponsesNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	invokeOptions []llm.InvokeOptions,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	requestStarted time.Time,
	originalInput any,
) {
	requestID := newResponseID()
	pr, pw := io.Pipe()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization)
	result, err := adapter.CollectAnthropicText(pr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.responses_collect_failed model=%q err=%v\n", req.Model, err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, 502, "provider_error", time.Since(requestStarted).Seconds())
		}
		writeError(conn, 502, "provider error")
		return
	}
	inputTokens := trustedrouter.EstimateInputTokens(req)
	outputTokens := trustedrouter.EstimateOutputTokensFromBytes(len(result.Text))
	var body bytes.Buffer
	if err := adapter.WriteResponsesResponse(&body, requestID, req.Model, result.Text, inputTokens, outputTokens, time.Now().Unix()); err != nil {
		writeError(conn, 500, "responses encoding error")
		return
	}
	writeJSONResponse(conn, 200, body.Bytes())
	settleAndBroadcast(
		ctx,
		trGateway,
		authorization,
		secretCache,
		trustedrouter.Usage{
			RequestID:         requestID,
			InputTokens:       inputTokens,
			OutputTokens:      outputTokens,
			ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
			FirstTokenSeconds: 0,
			UsageEstimated:    true,
			FinishReason:      result.FinishReason,
			Streamed:          false,
			RouteType:         "responses",
			User:              req.User,
			SessionID:         req.SessionID,
			Trace:             req.Trace,
			Metadata:          req.Metadata,
		},
		req,
		originalInput,
		result.Text,
	)
}

func serveStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	invokeOptions []llm.InvokeOptions,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	requestStarted time.Time,
	originalInput any,
	routeType string,
) {
	requestID := newRequestID()
	if routeType == "responses" {
		requestID = newResponseID()
	}
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		return
	}

	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)

	pr, pw := io.Pipe()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization)

	var result adapter.StreamResult
	var err error
	if routeType == "responses" {
		result, err = adapter.TransformResponsesStream(pr, statsW, requestID, req.Model, trustedrouter.EstimateInputTokens(req))
	} else {
		result, err = adapter.TransformStreamCapture(pr, statsW, requestID, req.Model)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.transform_stream_failed model=%q err=%v\n", req.Model, err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, 502, "provider_error", time.Since(requestStarted).Seconds())
		}
		return
	}
	settleAndBroadcast(
		ctx,
		trGateway,
		authorization,
		secretCache,
		trustedrouter.Usage{
			RequestID:         requestID,
			InputTokens:       trustedrouter.EstimateInputTokens(req),
			OutputTokens:      trustedrouter.EstimateOutputTokensFromBytes(len(result.Text)),
			ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
			FirstTokenSeconds: statsW.FirstWriteSeconds(requestStarted),
			UsageEstimated:    true,
			FinishReason:      result.FinishReason,
			Streamed:          true,
			RouteType:         routeType,
			User:              req.User,
			SessionID:         req.SessionID,
			Trace:             req.Trace,
			Metadata:          req.Metadata,
		},
		req,
		originalInput,
		result.Text,
	)
}

func invokeProviderStream(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	pw *io.PipeWriter,
	invokeOptions []llm.InvokeOptions,
	trEnabled bool,
	authorization *trustedrouter.Authorization,
) {
	if err := br.InvokeStreaming(ctx, req, anthropicReq, pw, invokeOptions...); err != nil {
		fmt.Fprintf(os.Stderr, "enclave.invoke_streaming_failed model=%q endpoint=%q err=%v\n",
			req.Model,
			func() string {
				if authorization != nil {
					return authorization.EndpointID
				}
				return ""
			}(),
			err)
		if trEnabled {
			_ = pw.CloseWithError(err)
			return
		}
		emitErrorAsAnthropicSSE(pw, err)
	}
	_ = pw.Close()
}

func settleAndBroadcast(
	ctx context.Context,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	usage trustedrouter.Usage,
	req *types.OpenAIChatRequest,
	originalInput any,
	output string,
) {
	if trGateway == nil || !trGateway.Enabled() || authorization == nil {
		return
	}
	result, err := trGateway.Settle(ctx, authorization, usage)
	if err != nil {
		return
	}
	go broadcast.DeliverContent(
		context.Background(),
		nil,
		secretCache,
		authorization.BroadcastDestinations,
		broadcast.Generation{
			ID:                result.GenerationID,
			WorkspaceID:       authorization.WorkspaceID,
			APIKeyHash:        authorization.APIKeyHash,
			Model:             result.Model,
			Provider:          result.Provider,
			Region:            result.Region,
			RouteType:         usage.RouteType,
			RequestID:         usage.RequestID,
			InputTokens:       usage.InputTokens,
			OutputTokens:      usage.OutputTokens,
			ElapsedSeconds:    usage.ElapsedSeconds,
			FirstTokenSeconds: usage.FirstTokenSeconds,
			Streamed:          usage.Streamed,
			FinishReason:      usage.FinishReason,
			CostMicrodollars:  result.CostMicrodollars,
			User:              req.User,
			SessionID:         req.SessionID,
			Trace:             req.Trace,
			Metadata:          req.Metadata,
		},
		originalInput,
		output,
	)
}

func providerAPIKey(
	ctx context.Context,
	cache *byokcache.Cache,
	authorization *trustedrouter.Authorization,
) (string, error) {
	if authorization == nil || !strings.EqualFold(authorization.UsageType, "BYOK") {
		return "", nil
	}
	if authorization.BYOKEncryptedSecret != nil {
		if cache == nil {
			return "", fmt.Errorf("byok cache is not configured")
		}
		secret, _, err := cache.Resolve(
			ctx,
			authorization.WorkspaceID,
			authorization.Provider,
			authorization.BYOKCacheKey,
			*authorization.BYOKEncryptedSecret,
		)
		return secret, err
	}
	if strings.HasPrefix(authorization.BYOKSecretRef, "env://") {
		name := strings.TrimPrefix(authorization.BYOKSecretRef, "env://")
		if value := os.Getenv(name); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("BYOK env ref %s is unset", name)
	}
	if strings.HasPrefix(authorization.BYOKSecretRef, "byok://") {
		return "", fmt.Errorf("BYOK envelope is missing for %s", authorization.BYOKSecretRef)
	}
	return "", nil
}

func statusFromControlPlaneError(err error) int {
	message := err.Error()
	for _, status := range []int{400, 401, 402, 403, 404, 429} {
		if strings.Contains(message, fmt.Sprintf("http %d", status)) {
			return status
		}
	}
	return 502
}

type streamStatsWriter struct {
	w         io.Writer
	bytes     int
	firstByte time.Time
}

func newStreamStatsWriter(w io.Writer) *streamStatsWriter {
	return &streamStatsWriter{w: w}
}

func (w *streamStatsWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && w.firstByte.IsZero() {
		w.firstByte = time.Now()
	}
	n, err := w.w.Write(p)
	w.bytes += n
	return n, err
}

func (w *streamStatsWriter) BytesWritten() int {
	return w.bytes
}

func (w *streamStatsWriter) FirstWriteSeconds(start time.Time) float64 {
	if w.firstByte.IsZero() {
		return 0
	}
	return maxDurationSeconds(w.firstByte.Sub(start), 0.001)
}

func maxDurationSeconds(duration time.Duration, floor float64) float64 {
	seconds := duration.Seconds()
	if seconds < floor {
		return floor
	}
	return seconds
}

// emitErrorAsAnthropicSSE turns an upstream-LLM failure into a small
// Anthropic-shaped SSE conversation: a content_block_delta carrying the
// API error text, followed by message_stop. The adapter then translates
// these to OpenAI chunks so the client sees `[upstream: <code>: <message>]`
// as the assistant's reply.
//
// Trust note: upstream API error responses contain only the error
// code/message (e.g. "ValidationException: max_tokens must be > 0",
// "Insufficient credits", etc.). They never echo back the user's prompt
// or any completion text, so emitting them verbatim keeps our
// zero-prompt-retention property intact.
//
// classifyUpstreamError is provided per-cloud (smithy unwrap on AWS,
// plain error.Error() on GCP) so this file stays cloud-agnostic.
func emitErrorAsAnthropicSSE(w io.Writer, err error) {
	code, msg := classifyUpstreamError(err)
	text := fmt.Sprintf("[upstream: %s: %s]", code, msg)

	delta := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	deltaJSON, _ := json.Marshal(delta)
	fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaJSON)

	stopDelta := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn"},
	}
	stopJSON, _ := json.Marshal(stopDelta)
	fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", stopJSON)
	fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

// asAdapterErr is the local errors.As substitute (no extra imports).
func asAdapterErr(err error, target **adapter.AdapterError) bool {
	for cur := err; cur != nil; {
		if e, ok := cur.(*adapter.AdapterError); ok {
			*target = e
			return true
		}
		// crude unwrap: errors.Unwrap from wrapper%w chains
		type unwrapper interface{ Unwrap() error }
		u, ok := cur.(unwrapper)
		if !ok {
			break
		}
		cur = u.Unwrap()
	}
	return false
}

// readRequest reads a minimal HTTP/1.1 request: status line + headers + body.
// Returns method + path + bearer + body. We don't validate Host or any
// other field; the dispatch happens by path in serveOne.
func readRequest(r net.Conn) (method, path, bearer string, body []byte, err error) {
	br := bufio.NewReader(r)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return "", "", "", nil, err
	}
	// "GET /path HTTP/1.1\r\n" — split into 3 fields
	parts := strings.Fields(statusLine)
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	contentLength := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", "", nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "authorization":
			if strings.HasPrefix(v, "Bearer ") {
				bearer = v[len("Bearer "):]
			}
		case "content-length":
			parsed, parseErr := strconv.Atoi(v)
			if parseErr != nil || parsed < 0 {
				return "", "", "", nil, fmt.Errorf("invalid content-length")
			}
			if parsed > maxRequestBodyBytes {
				return "", "", "", nil, errBodyTooLarge
			}
			contentLength = parsed
		}
	}
	body = make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(br, body); err != nil {
			return "", "", "", nil, err
		}
	}
	return method, path, bearer, body, nil
}

func parseRequestTarget(rawPath string) (string, []byte, error) {
	u, err := url.ParseRequestURI(rawPath)
	if err != nil {
		return rawPath, nil, nil
	}
	nonceHex := u.Query().Get("nonce")
	if nonceHex == "" {
		return u.Path, nil, nil
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid attestation nonce")
	}
	if len(nonce) > maxAttestationNonceBytes {
		return "", nil, fmt.Errorf("attestation nonce too large")
	}
	return u.Path, nonce, nil
}

// serveAttestation answers GET /attestation with the NSM-signed CBOR
// document binding the live TLS cert's public key. Clients fetch this
// before sending prompts; verify against AWS's NSM root + check PCR0
// matches the trust page's published value + check the cert presented in
// their TLS handshake matches the doc's PublicKey field.
//
// nonce: ?nonce=<hex> in the query string. Optional but recommended —
// a client-supplied freshness token so the doc is provably not a replay.
func serveAttestation(conn io.Writer, tlsServer *enclavetls.Server, deviceBlob, nonce []byte) {
	var leafDER []byte
	if tlsServer != nil {
		leafDER = tlsServer.CurrentLeafDER()
	}
	if leafDER == nil {
		writeError(conn, 503, "TLS not enabled in this enclave; attestation requires a bound cert")
		return
	}
	doc, err := attestation.Get(leafDER, deviceBlob, nonce)
	if err != nil {
		writeError(conn, 500, "attestation: "+err.Error())
		return
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		len(doc))
	conn.Write(doc)
}

func writeError(w io.Writer, status int, message string) {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"status": status, "message": message},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
	w.Write(body)
}

func writeJSONResponse(w io.Writer, status int, body []byte) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
	w.Write(body)
}

func writeResponseHead(w io.Writer, status int, contentType string) error {
	if contentType == "" {
		contentType = "text/event-stream"
	}
	_, err := fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\nContent-Type: %s\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n",
		status, statusText(status), contentType)
	return err
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 413:
		return "Payload Too Large"
	case 404:
		return "Not Found"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 500:
		return "Internal Server Error"
	default:
		return "Error"
	}
}

// chunkedWriter wraps a net.Conn writer with HTTP/1.1 chunked transfer-encoding.
type chunkedWriter struct {
	w io.Writer
}

func newChunkedWriter(w io.Writer) *chunkedWriter { return &chunkedWriter{w: w} }

func (c *chunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(c.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if _, err := c.w.Write([]byte("\r\n")); err != nil {
		return n, err
	}
	return n, nil
}

func (c *chunkedWriter) Close() error {
	_, err := c.w.Write([]byte("0\r\n\r\n"))
	return err
}

// newRequestID returns "chatcmpl-<32 hex>" with no allocations beyond the buffer.
func newRequestID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "chatcmpl-" + hex.EncodeToString(buf[:])
}

func newResponseID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "resp_" + hex.EncodeToString(buf[:])
}
