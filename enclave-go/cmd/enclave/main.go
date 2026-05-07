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
	"sync"
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
	if strings.HasPrefix(routePath, "/v1/conversations") {
		if !validateMetadataRoute(ctx, conn, trGateway, bearer, "conversations") {
			return
		}
		writeOpenAIError(conn, 501, "not_supported_in_alpha", "not_supported_in_alpha", "not_supported_in_alpha", "conversations")
		return
	}
	if routePath == "/v1/responses/input_tokens" {
		if method != "POST" {
			writeOpenAIError(conn, 404, "route not found", "invalid_request_error", "not_found", "")
			return
		}
		if !validateMetadataRoute(ctx, conn, trGateway, bearer, "responses.input_tokens") {
			return
		}
		serveResponsesInputTokens(conn, body)
		return
	}
	if isUnsupportedResponsesEndpoint(method, routePath) {
		if !validateMetadataRoute(ctx, conn, trGateway, bearer, "responses.stub") {
			return
		}
		writeOpenAIError(conn, 501, "not_supported_in_alpha", "not_supported_in_alpha", "not_supported_in_alpha", routePath)
		return
	}
	if routePath == "/v1/responses" {
		if method != "POST" {
			writeOpenAIError(conn, 404, "route not found", "invalid_request_error", "not_found", "")
			return
		}
		routeType = "responses"
		responsesReq, err := parseResponsesRequest(body)
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeAdapterOpenAIError(conn, aerr)
				return
			}
			writeOpenAIError(conn, 400, "invalid JSON", "invalid_request_error", "bad_request", "")
			return
		}
		chatReq, err := adapter.ResponsesToChat(responsesReq)
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeAdapterOpenAIError(conn, aerr)
				return
			}
			writeOpenAIError(conn, 400, "invalid responses request", "invalid_request_error", "bad_request", "")
			return
		}
		req = *chatReq
		originalInput = responsesReq.Input
	} else if routePath == "/v1/chat/completions" {
		if method != "POST" {
			writeError(conn, 404, "route not found")
			return
		}
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
		req.Models = nil
		invokeOptions, err = invokeOptionsForAuthorization(ctx, byokSecrets, authorization)
		if err != nil {
			_ = trGateway.Refund(ctx, authorization, 502, "byok_secret_error", time.Since(requestStarted).Seconds())
			writeError(conn, 502, "BYOK provider key unavailable")
			return
		}
		if len(invokeOptions) > 0 && invokeOptions[0].Model != "" {
			req.Model = invokeOptions[0].Model
		} else {
			req.Model = authorization.Model
		}
	}
	if !req.Stream {
		if routeType == "responses" {
			serveResponsesNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput)
			return
		}
		serveChatNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput)
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

func validateMetadataRoute(
	ctx context.Context,
	conn io.Writer,
	trGateway *trustedrouter.Client,
	bearer string,
	routeType string,
) bool {
	if trGateway == nil || !trGateway.Enabled() {
		return true
	}
	if err := trGateway.ValidateKey(ctx, bearer, routeType); err != nil {
		writeError(conn, statusFromControlPlaneError(err), "gateway authorization failed")
		return false
	}
	return true
}

func parseResponsesInputTokensRequest(body []byte) (*types.OpenAIResponsesRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if err := adapter.RejectUnsupportedResponsesInputTokenFields(raw); err != nil {
		return nil, err
	}
	var req types.OpenAIResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func serveResponsesInputTokens(conn io.Writer, body []byte) {
	responsesReq, err := parseResponsesInputTokensRequest(body)
	if err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeAdapterOpenAIError(conn, aerr)
			return
		}
		writeOpenAIError(conn, 400, "invalid JSON", "invalid_request_error", "bad_request", "")
		return
	}
	chatReq, err := adapter.ResponsesToChat(responsesReq)
	if err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeAdapterOpenAIError(conn, aerr)
			return
		}
		writeOpenAIError(conn, 400, "invalid responses request", "invalid_request_error", "bad_request", "")
		return
	}
	var out bytes.Buffer
	if err := adapter.WriteResponsesInputTokens(&out, trustedrouter.EstimateInputTokens(chatReq)); err != nil {
		writeOpenAIError(conn, 500, "responses encoding error", "server_error", "internal_error", "")
		return
	}
	writeJSONResponse(conn, 200, out.Bytes())
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
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute)
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
	outputTokens := trustedrouter.EstimateOutputTokens(result.Text)
	selectedModel := selectedRoute.Model(req.Model, authorization)
	selectedEndpoint := selectedRoute.Endpoint("", authorization)
	if selectedModel != "" {
		req.Model = selectedModel
	}
	var body bytes.Buffer
	if err := adapter.WriteResponsesResponse(&body, requestID, req.Model, result.Text, inputTokens, outputTokens, time.Now().Unix()); err != nil {
		writeError(conn, 500, "responses encoding error")
		return
	}
	usage := trustedrouter.Usage{
		RequestID:         requestID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: 0,
		UsageEstimated:    true,
		FinishReason:      result.FinishReason,
		Streamed:          false,
		RouteType:         "responses",
		SelectedModel:     selectedModel,
		SelectedEndpoint:  selectedEndpoint,
		User:              req.User,
		SessionID:         req.SessionID,
		Trace:             req.Trace,
		Metadata:          req.Metadata,
	}
	if _, err := settleAndBroadcast(ctx, trGateway, authorization, secretCache, usage, req, originalInput, result.Text); err != nil {
		fmt.Fprintf(os.Stderr, "enclave.responses_settle_failed model=%q err=%v\n", req.Model, err)
		writeError(conn, 502, "settlement failed")
		return
	}
	writeJSONResponse(conn, 200, body.Bytes())
}

func serveChatNonStreaming(
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
	requestID := newRequestID()
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute)
	result, err := adapter.CollectAnthropicText(pr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.chat_collect_failed model=%q err=%v\n", req.Model, err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, 502, "provider_error", time.Since(requestStarted).Seconds())
		}
		writeError(conn, 502, "provider error")
		return
	}
	inputTokens := trustedrouter.EstimateInputTokens(req)
	outputTokens := trustedrouter.EstimateOutputTokens(result.Text)
	selectedModel := selectedRoute.Model(req.Model, authorization)
	selectedEndpoint := selectedRoute.Endpoint("", authorization)
	if selectedModel != "" {
		req.Model = selectedModel
	}
	var body bytes.Buffer
	if err := adapter.WriteChatCompletionResponse(&body, requestID, req.Model, result.Text, inputTokens, outputTokens, time.Now().Unix(), result.FinishReason); err != nil {
		writeError(conn, 500, "chat completion encoding error")
		return
	}
	usage := trustedrouter.Usage{
		RequestID:         requestID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: 0,
		UsageEstimated:    true,
		FinishReason:      result.FinishReason,
		Streamed:          false,
		RouteType:         "chat.completions",
		SelectedModel:     selectedModel,
		SelectedEndpoint:  selectedEndpoint,
		User:              req.User,
		SessionID:         req.SessionID,
		Trace:             req.Trace,
		Metadata:          req.Metadata,
	}
	if _, err := settleAndBroadcast(ctx, trGateway, authorization, secretCache, usage, req, originalInput, result.Text); err != nil {
		fmt.Fprintf(os.Stderr, "enclave.chat_settle_failed model=%q err=%v\n", req.Model, err)
		writeError(conn, 502, "settlement failed")
		return
	}
	writeJSONResponse(conn, 200, body.Bytes())
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
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	providerDone := make(chan struct{})
	go func() {
		defer close(providerDone)
		invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute)
	}()
	if trGateway != nil && trGateway.Enabled() && len(invokeOptions) > 1 {
		select {
		case <-selectedRoute.Ready():
		case <-providerDone:
		}
	} else if len(invokeOptions) > 0 {
		selectedRoute.Select(invokeOptions[0])
	}
	streamModel := selectedRoute.Model(req.Model, authorization)
	if streamModel != "" {
		req.Model = streamModel
	}
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		_ = pr.Close()
		return
	}

	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)

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
		if routeType == "responses" || statsW.BytesWritten() == 0 {
			_ = writeStreamingProviderError(statsW, routeType, requestID, req.Model)
		}
		return
	}
	if _, err := settleAndBroadcast(
		ctx,
		trGateway,
		authorization,
		secretCache,
		trustedrouter.Usage{
			RequestID:         requestID,
			InputTokens:       trustedrouter.EstimateInputTokens(req),
			OutputTokens:      trustedrouter.EstimateOutputTokens(result.Text),
			ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
			FirstTokenSeconds: statsW.FirstWriteSeconds(requestStarted),
			UsageEstimated:    true,
			FinishReason:      result.FinishReason,
			Streamed:          true,
			RouteType:         routeType,
			SelectedModel:     selectedRoute.Model(req.Model, authorization),
			SelectedEndpoint:  selectedRoute.Endpoint("", authorization),
			User:              req.User,
			SessionID:         req.SessionID,
			Trace:             req.Trace,
			Metadata:          req.Metadata,
		},
		req,
		originalInput,
		result.Text,
	); err != nil {
		fmt.Fprintf(os.Stderr, "enclave.stream_settle_failed model=%q route_type=%q err=%v\n", req.Model, routeType, err)
	}
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
	selectedRoute *selectedRouteTracker,
) {
	options := invokeOptions
	if len(options) == 0 {
		options = []llm.InvokeOptions{{Model: req.Model}}
	}
	var lastErr error
	for i, option := range options {
		if option.Model == "" {
			option.Model = req.Model
		}
		req.Model = option.Model
		// Per-attempt time-to-first-byte deadline. If the upstream
		// provider doesn't deliver a single byte within
		// firstByteBudget, cancel this attempt and fall through to
		// the next candidate. The cancel is *disarmed* the moment
		// the candidateWriter sees its first byte, so once streaming
		// starts the call can run as long as the underlying HTTP
		// client allows (~10 min). Without this, a hung upstream
		// blocks the whole 10-min budget before the next candidate
		// gets a chance.
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		var ttfbFired bool
		ttfbTimer := time.AfterFunc(firstByteBudget, func() {
			ttfbFired = true
			cancelAttempt()
		})
		candidateWriter := &routeSelectingWriter{
			w:       pw,
			tracker: selectedRoute,
			option:  option,
			onFirstByte: func() {
				// First byte arrived from upstream; disarm the TTFB cancel.
				ttfbTimer.Stop()
			},
		}
		err := br.InvokeStreaming(attemptCtx, req, anthropicReq, candidateWriter, option)
		ttfbTimer.Stop()
		cancelAttempt()
		if ttfbFired && err != nil {
			// Surface a recognizable error so retryableInvokeError below
			// classifies it correctly; the upstream's own ctx-canceled
			// error wrappers vary across clients.
			err = fmt.Errorf("llm/upstream: time-to-first-byte exceeded %s: %w", firstByteBudget, err)
		}
		if err == nil {
			if candidateWriter.BytesWritten() == 0 {
				selectedRoute.Select(option)
			}
			_ = pw.Close()
			return
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "enclave.invoke_streaming_failed model=%q endpoint=%q provider=%q attempt=%d/%d err=%v\n",
			option.Model,
			option.EndpointID,
			option.Provider,
			i+1,
			len(options),
			err)
		if !trEnabled || candidateWriter.BytesWritten() > 0 || i == len(options)-1 || !retryableInvokeError(err) {
			if trEnabled {
				_ = pw.CloseWithError(err)
				return
			}
			emitErrorAsAnthropicSSE(pw, err)
			_ = pw.Close()
			return
		}
	}
	if lastErr != nil {
		_ = pw.CloseWithError(lastErr)
		return
	}
	_ = pw.Close()
}

type selectedRouteTracker struct {
	mu       sync.Mutex
	once     sync.Once
	ready    chan struct{}
	model    string
	endpoint string
}

func newSelectedRouteTracker() *selectedRouteTracker {
	return &selectedRouteTracker{ready: make(chan struct{})}
}

func (t *selectedRouteTracker) Select(option llm.InvokeOptions) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.model == "" && option.Model != "" {
		t.model = option.Model
	}
	if t.endpoint == "" && option.EndpointID != "" {
		t.endpoint = option.EndpointID
	}
	t.mu.Unlock()
	t.once.Do(func() {
		close(t.ready)
	})
}

func (t *selectedRouteTracker) Ready() <-chan struct{} {
	if t == nil {
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	return t.ready
}

func (t *selectedRouteTracker) Model(fallback string, authorization *trustedrouter.Authorization) string {
	if t != nil {
		t.mu.Lock()
		model := t.model
		t.mu.Unlock()
		if model != "" {
			return model
		}
	}
	if fallback != "" {
		return fallback
	}
	if authorization != nil {
		return authorization.Model
	}
	return ""
}

func (t *selectedRouteTracker) Endpoint(fallback string, authorization *trustedrouter.Authorization) string {
	if t != nil {
		t.mu.Lock()
		endpoint := t.endpoint
		t.mu.Unlock()
		if endpoint != "" {
			return endpoint
		}
	}
	if fallback != "" {
		return fallback
	}
	if authorization != nil {
		return authorization.EndpointID
	}
	return ""
}

// firstByteBudget caps how long a single provider attempt may take
// before delivering its first byte. With a typical 3-candidate
// fallback chain this means a hung provider costs ~8s of the
// customer's budget, not the underlying HTTP client's 10-min total
// timeout. Override at boot via QUILL_FIRST_BYTE_TIMEOUT_SECONDS.
var firstByteBudget = func() time.Duration {
	raw := os.Getenv("QUILL_FIRST_BYTE_TIMEOUT_SECONDS")
	if raw == "" {
		return 8 * time.Second
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 8 * time.Second
}()

type routeSelectingWriter struct {
	w           io.Writer
	tracker     *selectedRouteTracker
	option      llm.InvokeOptions
	bytes       int
	onFirstByte func() // optional: invoked exactly once when the first byte arrives
	firstByte   sync.Once
}

func (w *routeSelectingWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.tracker.Select(w.option)
		if w.onFirstByte != nil {
			w.firstByte.Do(w.onFirstByte)
		}
	}
	n, err := w.w.Write(p)
	w.bytes += n
	return n, err
}

func (w *routeSelectingWriter) BytesWritten() int {
	if w == nil {
		return 0
	}
	return w.bytes
}

func retryableInvokeError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "http 429") ||
		strings.Contains(message, "status 429") ||
		strings.Contains(message, "too many requests") ||
		strings.Contains(message, "rate limit") ||
		strings.Contains(message, "http 5") ||
		strings.Contains(message, "status 5") ||
		strings.Contains(message, "timeout") ||
		strings.Contains(message, "temporary") ||
		// TTFB-canceled attempts: the upstream didn't return a single
		// byte within firstByteBudget. Always retryable — the next
		// candidate may be healthy.
		strings.Contains(message, "time-to-first-byte exceeded") ||
		strings.Contains(message, "context canceled") ||
		strings.Contains(message, "context deadline exceeded")
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
) (*trustedrouter.SettleResult, error) {
	if trGateway == nil || !trGateway.Enabled() || authorization == nil {
		return nil, nil
	}
	result, err := trGateway.Settle(ctx, authorization, usage)
	if err != nil {
		return nil, err
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
	return result, nil
}

func writeStreamingProviderError(w io.Writer, routeType, requestID, model string) error {
	errBody := map[string]any{
		"message": "provider error",
		"type":    "provider_error",
	}
	if routeType == "responses" {
		payload := map[string]any{
			"type": "response.failed",
			"response": map[string]any{
				"id":         requestID,
				"object":     "response",
				"created_at": time.Now().Unix(),
				"model":      model,
				"status":     "failed",
				"error":      errBody,
			},
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: response.failed\ndata: %s\n\n", encoded); err != nil {
			return err
		}
		_, err = io.WriteString(w, "data: [DONE]\n\n")
		return err
	}
	payload := map[string]any{"error": errBody}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", encoded); err != nil {
		return err
	}
	_, err = io.WriteString(w, "data: [DONE]\n\n")
	return err
}

func invokeOptionsForAuthorization(
	ctx context.Context,
	cache *byokcache.Cache,
	authorization *trustedrouter.Authorization,
) ([]llm.InvokeOptions, error) {
	if authorization == nil {
		return nil, nil
	}
	candidates := authorization.RouteCandidates
	if len(candidates) == 0 {
		candidates = []trustedrouter.RouteCandidate{{
			EndpointID:          authorization.EndpointID,
			Model:               authorization.Model,
			UpstreamModel:       authorization.UpstreamModel,
			Provider:            authorization.Provider,
			UsageType:           authorization.UsageType,
			BYOKSecretRef:       authorization.BYOKSecretRef,
			BYOKEncryptedSecret: authorization.BYOKEncryptedSecret,
			BYOKCacheKey:        authorization.BYOKCacheKey,
		}}
	}
	options := make([]llm.InvokeOptions, 0, len(candidates))
	var unavailable []string
	for _, candidate := range candidates {
		if candidate.Model == "" {
			candidate.Model = authorization.Model
		}
		if candidate.UpstreamModel == "" {
			candidate.UpstreamModel = candidate.Model
		}
		if candidate.EndpointID == "" {
			candidate.EndpointID = authorization.EndpointID
		}
		if candidate.Provider == "" {
			candidate.Provider = authorization.Provider
		}
		if candidate.UsageType == "" {
			candidate.UsageType = authorization.UsageType
		}
		providerKey, err := providerAPIKeyForRoute(ctx, cache, authorization.WorkspaceID, candidate)
		if err != nil {
			unavailable = append(unavailable, fmt.Sprintf("%s: %v", candidate.EndpointID, err))
			continue
		}
		options = append(options, llm.InvokeOptions{
			Model:          candidate.Model,
			UpstreamModel:  candidate.UpstreamModel,
			ProviderAPIKey: providerKey,
			Provider:       candidate.Provider,
			EndpointID:     candidate.EndpointID,
			UsageType:      candidate.UsageType,
		})
	}
	if len(options) == 0 && len(unavailable) > 0 {
		return nil, fmt.Errorf("no authorized route candidate has an available provider key: %s", strings.Join(unavailable, "; "))
	}
	return options, nil
}

func providerAPIKeyForRoute(
	ctx context.Context,
	cache *byokcache.Cache,
	workspaceID string,
	candidate trustedrouter.RouteCandidate,
) (string, error) {
	if !strings.EqualFold(candidate.UsageType, "BYOK") {
		return "", nil
	}
	if candidate.BYOKEncryptedSecret != nil {
		if cache == nil {
			return "", fmt.Errorf("byok cache is not configured")
		}
		secret, _, err := cache.Resolve(
			ctx,
			workspaceID,
			candidate.Provider,
			candidate.BYOKCacheKey,
			*candidate.BYOKEncryptedSecret,
		)
		return secret, err
	}
	if strings.HasPrefix(candidate.BYOKSecretRef, "env://") {
		name := strings.TrimPrefix(candidate.BYOKSecretRef, "env://")
		if value := os.Getenv(name); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("BYOK env ref %s is unset", name)
	}
	if strings.HasPrefix(candidate.BYOKSecretRef, "byok://") {
		return "", fmt.Errorf("BYOK envelope is missing for %s", candidate.BYOKSecretRef)
	}
	return "", fmt.Errorf("BYOK provider key reference is missing")
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

func isUnsupportedResponsesEndpoint(method, routePath string) bool {
	if !strings.HasPrefix(routePath, "/v1/responses/") {
		return false
	}
	if method == "GET" && strings.HasSuffix(routePath, "/input_items") {
		return true
	}
	if method == "POST" && strings.HasSuffix(routePath, "/cancel") {
		return true
	}
	if method == "POST" && routePath == "/v1/responses/compact" {
		return true
	}
	if method == "GET" && strings.Count(strings.TrimPrefix(routePath, "/v1/responses/"), "/") == 0 {
		return true
	}
	if method == "DELETE" && strings.Count(strings.TrimPrefix(routePath, "/v1/responses/"), "/") == 0 {
		return true
	}
	return false
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

func writeAdapterOpenAIError(w io.Writer, err *adapter.AdapterError) {
	errType := "invalid_request_error"
	code := "bad_request"
	if err.Status == 501 {
		errType = "not_supported_in_alpha"
		code = "not_supported_in_alpha"
	}
	writeOpenAIError(w, err.Status, err.Message, errType, code, err.Context)
}

func writeOpenAIError(w io.Writer, status int, message, errType, code, param string) {
	if errType == "" {
		errType = "invalid_request_error"
	}
	if code == "" {
		code = errType
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    errType,
			"param":   orNilString(param),
			"code":    code,
		},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
	w.Write(body)
}

func orNilString(value string) any {
	if value == "" {
		return nil
	}
	return value
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
