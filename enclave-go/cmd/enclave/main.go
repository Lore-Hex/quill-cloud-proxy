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
	"os/exec"
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

	method, path, bearer, body, err := readRequest(conn)
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
	requestLogID string,
) {
	options := invokeOptions
	if len(options) == 0 {
		options = []llm.InvokeOptions{{Model: req.Model}}
	}
	overallStart := time.Now()
	requestID := authorizationRequestID(authorization)
	var lastErr error
	var winningProvider, winningModel, winningEndpoint string
	var winningBytes int
	var winningTTFBms, winningTotalMs int64
	for i, option := range options {
		if option.Model == "" {
			option.Model = req.Model
		}
		req.Model = option.Model
		// Per-attempt time-to-first-byte deadline (see firstByteBudget).
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		var ttfbFired bool
		ttfbTimer := time.AfterFunc(firstByteBudget, func() {
			ttfbFired = true
			cancelAttempt()
		})
		attemptStart := time.Now()
		var ttfb time.Duration
		var ttfbCaptured bool
		candidateWriter := &routeSelectingWriter{
			w:       pw,
			tracker: selectedRoute,
			option:  option,
			onFirstByte: func() {
				// First byte arrived from upstream; disarm the TTFB cancel
				// and record the latency so we can log it.
				ttfb = time.Since(attemptStart)
				ttfbCaptured = true
				ttfbTimer.Stop()
			},
		}
		err := br.InvokeStreaming(attemptCtx, req, anthropicReq, candidateWriter, option)
		attemptDuration := time.Since(attemptStart)
		ttfbTimer.Stop()
		cancelAttempt()
		if ttfbFired && err != nil {
			err = fmt.Errorf("llm/upstream: time-to-first-byte exceeded %s: %w", firstByteBudget, err)
		}

		// Per-attempt structured log. One line, key=value, no prompt
		// or response content — just the metadata an operator needs
		// to attribute hangs/failures to a specific provider.
		ttfbMs := int64(-1)
		if ttfbCaptured {
			ttfbMs = ttfb.Milliseconds()
		}
		outcome := "ok"
		errStr := ""
		if err != nil {
			outcome = "fail"
			errStr = errorClass(err)
		}
		fmt.Fprintf(os.Stderr,
			"enclave.invoke_attempt request_log_id=%q request_id=%q attempt=%d/%d model=%q provider=%q endpoint=%q outcome=%s ttfb_ms=%d total_ms=%d bytes=%d err=%q\n",
			requestLogID,
			requestID,
			i+1, len(options),
			option.Model, option.Provider, option.EndpointID,
			outcome,
			ttfbMs,
			attemptDuration.Milliseconds(),
			candidateWriter.BytesWritten(),
			errStr,
		)

		if err == nil {
			if candidateWriter.BytesWritten() == 0 {
				selectedRoute.Select(option)
			}
			winningProvider, winningModel, winningEndpoint = option.Provider, option.Model, option.EndpointID
			winningBytes = candidateWriter.BytesWritten()
			winningTTFBms = ttfbMs
			winningTotalMs = attemptDuration.Milliseconds()
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_complete request_log_id=%q request_id=%q outcome=ok provider_used=%q model=%q endpoint=%q attempts=%d fallbacks=%d ttfb_ms=%d upstream_ms=%d total_ms=%d bytes=%d\n",
				requestLogID,
				requestID,
				winningProvider, winningModel, winningEndpoint,
				i+1, i,
				winningTTFBms,
				winningTotalMs,
				time.Since(overallStart).Milliseconds(),
				winningBytes,
			)
			_ = pw.Close()
			return
		}
		lastErr = err
		if !trEnabled || candidateWriter.BytesWritten() > 0 || i == len(options)-1 || !retryableInvokeError(err) {
			fmt.Fprintf(os.Stderr,
				"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
				requestLogID, requestID, i+1, i, time.Since(overallStart).Milliseconds(), errorClass(err),
			)
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
		fmt.Fprintf(os.Stderr,
			"enclave.invoke_complete request_log_id=%q request_id=%q outcome=fail attempts=%d fallbacks=%d total_ms=%d last_err=%q\n",
			requestLogID, requestID, len(options), len(options)-1, time.Since(overallStart).Milliseconds(), errorClass(lastErr),
		)
		_ = pw.CloseWithError(lastErr)
		return
	}
	_ = pw.Close()
}

// authorizationRequestID returns a stable correlation id for log
// lines. Falls back to "anon" so lines remain greppable even on
// pre-trustedrouter paths (legacy direct-Anthropic, etc.).
func authorizationRequestID(authorization *trustedrouter.Authorization) string {
	if authorization == nil {
		return "anon"
	}
	if id := authorization.AuthorizationID; id != "" {
		return id
	}
	return "anon"
}

// errorClass collapses an error to a short label suitable for log
// aggregation. We strip path/host fragments that vary per-request so
// "top errors of the hour" becomes a meaningful query.
func errorClass(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "time-to-first-byte exceeded"):
		return "ttfb_exceeded"
	case strings.Contains(msg, "context canceled"):
		return "ctx_canceled"
	case strings.Contains(msg, "context deadline exceeded"):
		return "ctx_deadline"
	case strings.Contains(strings.ToLower(msg), "http 5"):
		return "upstream_5xx"
	case strings.Contains(strings.ToLower(msg), "http 429"), strings.Contains(strings.ToLower(msg), "rate limit"):
		return "rate_limited"
	case strings.Contains(strings.ToLower(msg), "http 4"):
		return "upstream_4xx"
	}
	// Last resort: first 80 chars, no newlines.
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return strings.ReplaceAll(msg, "\n", " ")
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

var settlementRetries = newSettlementRetryQueueFromEnv()

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

type responseStatsConn struct {
	net.Conn
	mu            sync.Mutex
	status        int
	responseBytes int
}

func (c *responseStatsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status == 0 {
		c.status = parseHTTPStatus(p)
	}
	c.responseBytes += n
	return n, err
}

func (c *responseStatsConn) Snapshot() (status int, responseBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.responseBytes
}

func parseHTTPStatus(p []byte) int {
	if !bytes.HasPrefix(p, []byte("HTTP/")) {
		return 0
	}
	line := p
	if i := bytes.IndexByte(p, '\n'); i >= 0 {
		line = p[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return 0
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return status
}

func outcomeForStatus(status int) string {
	switch {
	case status >= 200 && status < 400:
		return "ok"
	case status >= 400 && status < 500:
		return "client_error"
	case status >= 500:
		return "server_error"
	default:
		return "no_response"
	}
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

func newRequestLogID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "rlog_" + hex.EncodeToString(buf[:])
}

// maybeStartAttestSidecar fork-execs the attest-sidecar binary if it
// exists at the conventional install path inside the enclave image
// (/attest-sidecar). If the binary isn't present (e.g., local dev
// builds, or a build configuration that doesn't ship the sidecar)
// this is a no-op — the main enclave still runs the in-process
// stdlib pin in tinfoil_attest.go, just without the cross-check.
//
// We pipe the sidecar's stdout/stderr into our own so its log lines
// show up in the same destination as the rest of the enclave logs
// (Cloud Logging + Axiom). The child inherits SIGTERM via process
// group; we don't bother explicitly tracking it because the Cloud
// Run / Confidential Space launcher kills the whole container.
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
