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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"
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

	// 0b. Fork-exec the attest-sidecar (a separate Go binary built
	// from enclave-go/sidecar/) so its full Sigstore + AMD VCEK
	// verification chain runs in its own process, isolated from the
	// main enclave's symbol table. The sidecar listens on the abstract
	// Unix socket "@tinfoil-attest"; tinfoil_attest.go in the llm
	// package picks it up and dual-sources the expected TLS public-key
	// fingerprint (in-process stdlib parse vs. sidecar's verified
	// value) on every tinfoil request — disagreement = refuse.
	//
	// Why not link the verifier into the main binary directly: the
	// transitive deps (sigstore-go, go-tuf/v2, certificate-transparency,
	// transparency-dev/merkle, mongo-driver, otel, grpc, protobuf)
	// corrupted the main enclave's vsock+TLS request loop on a previous
	// attempt — every request started returning HTTP 400 within minutes
	// of rollout (deploy 25592563258), tripping the canary at 2-min
	// consecutive-down. Sidecar isolation keeps that dep tree out of
	// the main enclave entirely.
	//
	// Sidecar failure is intentionally non-fatal here: the in-process
	// stdlib pin still holds even with no sidecar, so tinfoil traffic
	// continues to be TLS-bound to the public key in REPORT_DATA;
	// only the AMD-signature attestation is missing in that mode and
	// we log it loudly so it's visible in dashboards.
	maybeStartAttestSidecar()

	// 1. Fetch bootstrap data from parent.
	boot, err := bootstrap.Fetch(ctx)
	if err != nil {
		// Boot fatal: emit to stderr only in debug mode (--debug-mode shows console).
		fmt.Fprintf(os.Stderr, "bootstrap fetch failed: %v\n", err)
		os.Exit(1)
	}

	// 1b. Cross-cloud GCP credentials (AWS-side enclave path).
	//
	// The parent's bootstrap server pulls the AWS-KMS-wrapped GCP
	// service-account key from `quill/trustedrouter-aws-cross-cloud-sa-key`,
	// unwraps via the per-instance enclave CMK, and ships the plaintext
	// JSON in `boot.GCPServiceAccountKeyJSON`. The enclave writes it to a
	// tmpfs file and points GOOGLE_APPLICATION_CREDENTIALS at the path so
	// every downstream client library (gcscache's SA-key token path, the
	// AWS-side LLM provider transports that read GCP secrets, the BYOK
	// KMS unwrapper) finds the credential without each module repeating
	// the bootstrap-RPC + parse dance.
	//
	// tmpfs (/tmp inside the enclave is a memfs) keeps the key out of any
	// persistent storage. It lives only for the enclave's lifetime, gets
	// re-fetched on every cold start. Permissions 0600.
	//
	// On GCP-side enclaves boot.GCPServiceAccountKeyJSON is empty (the
	// metadata service is used instead) and this block no-ops, so the
	// same enclave binary handles both clouds.
	if strings.TrimSpace(boot.GCPServiceAccountKeyJSON) != "" {
		credPath := "/tmp/gcp-sa.json"
		if err := os.WriteFile(credPath, []byte(boot.GCPServiceAccountKeyJSON), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write GCP SA key tmpfs failed: %v\n", err)
			os.Exit(1)
		}
		if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credPath); err != nil {
			fmt.Fprintf(os.Stderr, "setenv GOOGLE_APPLICATION_CREDENTIALS failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "cross-cloud SA key wired: GOOGLE_APPLICATION_CREDENTIALS=%s\n", credPath)
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
		// On AWS, NewVsockKMSClient routes oauth2 + cloudkms over the
		// parent's vsock-proxy. On GCP it returns a stdlib client.
		// The TokenSource is shared from the same client so the JWT
		// exchange leg of the SA-key flow also tunnels correctly.
		kmsHTTP := byokcache.NewVsockKMSClient()
		byokSecrets = byokcache.New(byokcache.Options{
			Unwrapper: &byokcache.GoogleKMSUnwrapper{
				HTTPClient:  kmsHTTP,
				TokenSource: byokcache.NewMetadataTokenSource(kmsHTTP),
			},
		})
		settlementRetries.Start(ctx)
	}

	deviceBlob, _ := json.Marshal(boot.Devices)

	// 3. Listen on vsock/TCP. When QUILL_ENCLAVE_TLS=true, wrap the listener
	// with an enclave-owned cert so TLS is terminated INSIDE the attested
	// binary — i.e. the parent never sees plaintext, and the PCR0-measured
	// code is the first thing to handle the prompt bytes.
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

		// DNS-01 defense-in-depth: if a CF token is bootstrapped,
		// run a background renewer that uses Cloudflare DNS-01
		// instead of TLS-ALPN-01. Defends against the cases where
		// LE's TLS-ALPN-01 validation can't reach the enclave (e.g.,
		// sustained GCP-side outage that takes shared-cache
		// validation routing with it). The renewer runs alongside
		// autocert; both write to the same GCS cache, so whichever
		// produces a fresh cert first wins.
		if mode == "acme" &&
			strings.TrimSpace(boot.CloudflareAPIToken) != "" &&
			strings.TrimSpace(boot.CloudflareZoneID) != "" &&
			strings.TrimSpace(os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET")) != "" {
			enclavetls.SetDNS01Stderr(os.Stderr)
			enclavetls.StartDNS01Renewer(ctx, enclavetls.DNS01Config{
				DNSName:            apiHost,
				Email:              os.Getenv("QUILL_ACME_EMAIL"),
				DirectoryURL:       os.Getenv("QUILL_ACME_DIRECTORY_URL"),
				Cache:              enclavetls.NewGCSCache(os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET")),
				CloudflareAPIToken: boot.CloudflareAPIToken,
				CloudflareZoneID:   boot.CloudflareZoneID,
				HTTPClient:         enclavetls.NewDNS01HTTPClient(),
			})
			fmt.Fprintf(os.Stderr, "enclavetls.dns01_renewer_started host=%s zone=%s\n",
				apiHost, boot.CloudflareZoneID)
		}
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
	statsConn := &responseStatsConn{Conn: conn}
	conn = statsConn
	defer conn.Close()

	requestLogID := newRequestLogID()
	requestStartedAt := time.Now()
	requestMethod := "unknown"
	requestRoute := "unknown"
	requestBodyBytes := 0
	fmt.Fprintf(os.Stderr, "enclave.request_accept request_log_id=%q\n", requestLogID)
	defer func() {
		status, responseBytes := statsConn.Snapshot()
		fmt.Fprintf(os.Stderr,
			"enclave.request_end request_log_id=%q method=%q route=%q status=%d outcome=%q body_bytes=%d response_bytes=%d elapsed_ms=%d\n",
			requestLogID,
			requestMethod,
			requestRoute,
			status,
			outcomeForStatus(status),
			requestBodyBytes,
			responseBytes,
			time.Since(requestStartedAt).Milliseconds(),
		)
	}()

	method, path, bearer, idempotencyKey, body, err := readRequest(conn)
	requestMethod = method
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(conn, 413, "request body too large")
			return
		}
		writeError(conn, 400, "could not read request")
		return
	}
	requestBodyBytes = len(body)
	routePath, nonce, err := parseRequestTarget(path)
	requestRoute = routePath
	if err != nil {
		writeError(conn, 400, err.Error())
		return
	}
	fmt.Fprintf(os.Stderr,
		"enclave.request_start request_log_id=%q method=%q route=%q body_bytes=%d\n",
		requestLogID,
		method,
		routePath,
		len(body),
	)

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
	req.IdempotencyKey = idempotencyKey
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
	req.IdempotencyKey = idempotencyKey

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
			serveResponsesNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, requestLogID)
			return
		}
		serveChatNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, requestLogID)
		return
	}
	serveStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, routeType, requestLogID)
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
	requestLogID string,
) {
	requestID := newResponseID()
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID)
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
	requestLogID string,
) {
	requestID := newRequestID()
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID)
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
	requestLogID string,
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
		invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID)
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
	usage := trustedrouter.Usage{
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
	}
	if _, err := settleAndBroadcast(
		ctx,
		trGateway,
		authorization,
		secretCache,
		usage,
		req,
		originalInput,
		result.Text,
	); err != nil {
		fmt.Fprintf(os.Stderr,
			"enclave.stream_settle_failed request_log_id=%q request_id=%q model=%q route_type=%q err=%v\n",
			requestLogID,
			requestID,
			req.Model,
			routeType,
			err,
		)
		settlementRetries.Enqueue(settlementRetryJob{
			trGateway:     trGateway,
			authorization: authorization,
			secretCache:   secretCache,
			usage:         usage,
			req:           req,
			originalInput: originalInput,
			output:        result.Text,
			requestLogID:  requestLogID,
		})
	}
}

func maybeStartAttestSidecar() {
	const sidecarPath = "/attest-sidecar"
	if os.Getenv("QUILL_DISABLE_ATTEST_SIDECAR") == "1" {
		fmt.Fprintln(os.Stderr, "attest_sidecar.skipped reason=disabled_env")
		return
	}
	info, err := os.Stat(sidecarPath)
	if err != nil {
		// Not packaged — log and continue. tinfoil_attest.go will see
		// the sidecar socket as unreachable and run in raw-only mode.
		fmt.Fprintf(os.Stderr, "attest_sidecar.skipped reason=binary_missing path=%q err=%q\n", sidecarPath, err.Error())
		return
	}
	if info.Mode()&0o111 == 0 {
		fmt.Fprintf(os.Stderr, "attest_sidecar.skipped reason=binary_not_executable path=%q mode=%v\n", sidecarPath, info.Mode())
		return
	}
	cmd := exec.Command(sidecarPath)
	// Inherit stdout/stderr so the sidecar's logs land where the main
	// enclave's logs already go (Cloud Logging via container stdout).
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "attest_sidecar.start_failed err=%q\n", err.Error())
		return
	}
	// Pin the unix-dialer to ONLY accept connections whose peer PID is
	// this freshly-spawned child. Defends against an attacker who races
	// us to bind @tinfoil-attest (abstract sockets have no filesystem
	// permission bits, so this PID check is the lightest authentication
	// signal we can layer on). See SetExpectedSidecarPID + peerPID in
	// internal/llm.
	llm.SetExpectedSidecarPID(cmd.Process.Pid)
	fmt.Fprintf(os.Stderr, "attest_sidecar.started pid=%d path=%q\n", cmd.Process.Pid, sidecarPath)
	// Reap the child if it ever exits so it doesn't become a zombie.
	// We don't restart it — if the sidecar is sick, we serve in
	// raw-only mode rather than thrash, and a future deploy will
	// rebuild the image.
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "attest_sidecar.exited err=%q pid=%d\n", err.Error(), cmd.Process.Pid)
		} else {
			fmt.Fprintf(os.Stderr, "attest_sidecar.exited ok pid=%d\n", cmd.Process.Pid)
		}
	}()
}
