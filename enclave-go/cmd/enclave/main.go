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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
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

// Anthropic-compatible vision payloads expand significantly once images are
// base64-encoded inside JSON. Keep the request cap aligned with common upstream
// multimodal API limits while still bounding enclave memory per connection.
const maxRequestBodyBytes = 32 * 1024 * 1024

// Confidential Space accepts each nonce string up to 74 bytes. Caller nonces
// arrive as raw bytes here but are hex-encoded before launch, so 37 raw bytes
// is the largest value that stays inside CSP's limit (37*2 = 74) and anything
// larger is a client 400 instead of a downstream attestation-launch failure.
const maxAttestationNonceBytes = 37
const maxAttestationsPerConn = 8
const maxHealthRequestsPerConn = 128

var requestReadTimeout = 30 * time.Second

// Bound writes to clients that stop reading without limiting provider thinking
// time or total streaming duration. The deadline is renewed for every write.
var responseWriteTimeout = 30 * time.Second

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
	// Sidecar process failure is non-fatal to the enclave because other
	// providers remain usable. Tinfoil itself fails closed: without a fresh
	// full-chain sidecar result AND the independent in-process cross-check,
	// no Tinfoil request bytes are sent.
	maybeStartAttestSidecar()

	// 1. Fetch bootstrap data from parent.
	boot, err := bootstrap.Fetch(ctx)
	if err != nil {
		// Boot fatal: emit to stderr only in debug mode (--debug-mode shows console).
		fmt.Fprintf(os.Stderr, "bootstrap fetch failed: %v\n", err)
		os.Exit(1)
	}

	// 1b. Cross-cloud GCP credentials (AWS-side and Azure-side enclave paths).
	//
	// On AWS the parent's bootstrap server pulls the AWS-KMS-wrapped GCP
	// service-account key from `quill/trustedrouter-aws-cross-cloud-sa-key`,
	// unwraps via the per-instance enclave CMK, and ships the plaintext
	// JSON in `boot.GCPServiceAccountKeyJSON`. On Azure the same field is
	// filled from one entry of the encrypted bundle the enclave opens with
	// an SKR-released key, so no unattested process holds it. The enclave
	// writes it to a
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
		credPath := "/tmp/gcp-sa.json" // #nosec G101 -- tmpfs path for bootstrap-provided service account JSON, not a credential.
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
	configureFusionPrompts(boot)
	configureAdvisorPrompts(boot)
	configureResponsesWebSearch(boot.ExaAPIKey)

	// 2. Build registries. Capture a canonical hash of the device list
	// so /attestation can include it in the document's UserData — clients
	// learn the exact set of bearer tokens currently authorized, and any
	// silent rotation produces a new attestation.
	registry := auth.New(boot.Devices)
	deviceBlob, _ := json.Marshal(boot.Devices)
	br := llm.New(boot) // build-tag-gated: AWS Bedrock by default, GCP Vertex with -tags gcp
	trGateway := trustedrouter.NewFromBootstrap(boot)
	videoGateway = newVideoService(videoProviderKeys(boot), trGateway)
	videoGateway.Start(ctx)
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
		batchConfig, batchEnabled := productionBatchConfig()
		if batchEnabled {
			kmsHTTP := byokcache.NewVsockKMSClient()
			identity, identityErr := byokcache.NewConfidentialSpaceTokenSource(batchConfig.WIFProvider, kmsHTTP)
			if identityErr != nil {
				fmt.Fprintf(os.Stderr, "batch.service_start_failed err=%q\n", identityErr.Error())
				batchGateway = nil
			} else {
				kms := &byokcache.GoogleKMSUnwrapper{
					HTTPClient:  kmsHTTP,
					TokenSource: identity,
				}
				nativeProviders := nativeBatchProviders(boot)
				// Keep the authorizer available even when native submission is
				// disabled so a restarted worker can refund durable in-flight holds.
				nativeAuthorizer := &batchNativeAuthorizer{gateway: trGateway}
				batchGateway, err = batchapi.New(batchapi.Options{
					Store:                 batchapi.NewGCSStoreWithTokenSource(batchConfig.Bucket, identity),
					Protector:             &batchapi.EnvelopeProtector{KMS: kms, KeyName: batchConfig.KMSKey},
					Keys:                  trGateway,
					NativeAuthorizer:      nativeAuthorizer,
					NativeProviders:       nativeProviders,
					NativeSubmitProviders: nativeBatchSubmitProviders(nativeBatchSubmitAllowlist),
					Executor: &batchEnclaveExecutor{
						registry:   registry,
						backend:    br,
						deviceBlob: deviceBlob,
						gateway:    trGateway,
						byok:       byokSecrets,
					},
					Logf: func(format string, args ...any) {
						fmt.Fprintf(os.Stderr, format+"\n", args...)
					},
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "batch.service_start_failed err=%q\n", err.Error())
					batchGateway = nil
				} else {
					batchGateway.Start(ctx)
					fmt.Fprintf(os.Stderr, "batch.service_started bucket=%q\n", batchConfig.Bucket)
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "batch.service_disabled reason=unsupported_cloud")
		}
	}

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
		// Parsed BEFORE either path: a malformed EAB must stop the process
		// here, with a message naming the variable, rather than surface later
		// as an ACME signature error against a CA whose docs the operator is
		// reading for the first time during an outage.
		eab, eabErr := enclavetls.ExternalAccountBindingFromEnv(
			os.Getenv("QUILL_ACME_EAB_KID"),
			os.Getenv("QUILL_ACME_EAB_HMAC_KEY"),
		)
		if eabErr != nil {
			fmt.Fprintf(os.Stderr, "enclavetls acme eab: %v\n", eabErr)
			os.Exit(1)
		}
		// Fallback CA (task: LE outage must not be a total TLS outage). Same
		// fail-fast rule as the primary EAB: a malformed fallback must stop
		// the process now, not fail registration during the outage it exists
		// for. GTS and ZeroSSL both REQUIRE EAB, so a fallback directory
		// without one is almost certainly a misconfiguration — logged loudly,
		// not fatal, because Buypass-class CAs legitimately run without EAB.
		// Preferred source is the bootstrap secret ("<kid>:<hmac>", resolved
		// via Secret Manager alongside provider keys — never plaintext in
		// instance metadata); the plain env pair remains for dev/tests.
		fallbackKID := os.Getenv("QUILL_ACME_FALLBACK_EAB_KID")
		fallbackHMAC := os.Getenv("QUILL_ACME_FALLBACK_EAB_HMAC_KEY")
		if sealed := strings.TrimSpace(boot.ACMEFallbackEAB); sealed != "" {
			kid, hmac, found := strings.Cut(sealed, ":")
			if !found {
				fmt.Fprintf(os.Stderr,
					"enclavetls acme fallback eab secret: expected \"<kid>:<hmac>\"\n")
				os.Exit(1)
			}
			fallbackKID, fallbackHMAC = kid, hmac
		}
		fallbackEAB, fallbackEABErr := enclavetls.ExternalAccountBindingFromEnv(
			fallbackKID,
			fallbackHMAC,
		)
		if fallbackEABErr != nil {
			fmt.Fprintf(os.Stderr, "enclavetls acme fallback eab: %v\n", fallbackEABErr)
			os.Exit(1)
		}
		var fallbackCAs []enclavetls.DNS01CA
		if fallbackDir := strings.TrimSpace(
			os.Getenv("QUILL_ACME_FALLBACK_DIRECTORY_URL"),
		); fallbackDir != "" {
			if fallbackEAB == nil {
				fmt.Fprintf(os.Stderr,
					"enclavetls.acme_fallback_without_eab directory=%s — GTS/ZeroSSL "+
						"will refuse registration; set QUILL_ACME_FALLBACK_EAB_KID/"+
						"QUILL_ACME_FALLBACK_EAB_HMAC_KEY unless this CA needs none\n",
					fallbackDir)
			}
			fallbackCAs = append(fallbackCAs, enclavetls.DNS01CA{
				DirectoryURL:       fallbackDir,
				EAB:                fallbackEAB,
				AccountKeyCacheKey: enclavetls.AccountKeyCacheKeyForDirectory(fallbackDir),
			})
		}
		if mode == "acme" {
			tlsServer, err = enclavetls.NewACME(
				apiHost,
				os.Getenv("QUILL_ACME_EMAIL"),
				os.Getenv("QUILL_ACME_CACHE_DIR"),
				os.Getenv("QUILL_ACME_DIRECTORY_URL"),
				os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET"),
				eab,
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
		cloudDNSConfigured := strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_GCP_PROJECT")) != "" &&
			strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_MANAGED_ZONE")) != ""
		cloudflareConfigured := strings.TrimSpace(boot.CloudflareAPIToken) != "" &&
			strings.TrimSpace(boot.CloudflareZoneID) != ""
		if mode == "acme" &&
			(cloudDNSConfigured || cloudflareConfigured) &&
			strings.TrimSpace(os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET")) != "" {
			enclavetls.SetDNS01Stderr(os.Stderr)
			// QUILL_API_HOST is built as API_HOST followed by EXTRA_API_HOSTS
			// (tools/deploy-azure-aci.sh), so index 0 is the name DNS points at
			// and the rest are shared names this region also serves. Only the
			// latter need DNS-01 to bootstrap, because TLS-ALPN-01 for them
			// lands on whichever region DNS resolves to, never here.
			for i, dnsName := range strings.Split(apiHost, ",") {
				dnsName = strings.TrimSpace(dnsName)
				if dnsName == "" {
					continue
				}
				isSharedName := i > 0
				enclavetls.StartDNS01Renewer(ctx, enclavetls.DNS01Config{
					DNSName:        dnsName,
					AllowBootstrap: isSharedName,
					// Cloud DNS when the zone is configured, Cloudflare
					// otherwise. trustedrouter.com is served by Cloud DNS, so
					// without this the DNS-01 fallback cannot touch the zone
					// that matters and only looks configured.
					Provider:           dns01Provider(),
					Email:              os.Getenv("QUILL_ACME_EMAIL"),
					DirectoryURL:       os.Getenv("QUILL_ACME_DIRECTORY_URL"),
					Cache:              enclavetls.NewGCSCache(os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET")),
					CloudflareAPIToken: boot.CloudflareAPIToken,
					CloudflareZoneID:   boot.CloudflareZoneID,
					HTTPClient:         enclavetls.NewDNS01HTTPClient(),
					// Same binding as autocert's. Both register accounts, and
					// a CA that requires EAB rejects whichever one omits it —
					// so a renewer without it is a fallback that fails only
					// when it is finally needed.
					ExternalAccountBinding: eab,
					// The CA half of defense-in-depth: when the primary
					// directory fails an order, the renewer tries these in
					// order on the same tick.
					FallbackCAs: fallbackCAs,
				})
				// Log the provider that will actually publish the challenge.
				// This printed the Cloudflare zone unconditionally, so a Cloud
				// DNS deployment logged "zone=" and looked misconfigured while
				// being correct.
				providerName, zone := "cloudflare", boot.CloudflareZoneID
				if p := dns01Provider(); p != nil {
					providerName = p.Name()
					zone = strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_MANAGED_ZONE"))
				}
				fmt.Fprintf(os.Stderr,
					"enclavetls.dns01_renewer_started host=%s provider=%s zone=%s\n",
					dnsName, providerName, zone)
			}
		}
	}

	// LB health endpoint. The serving port (:443) terminates TLS inside the
	// enclave, so the GCP passthrough-NLB's TCP/SSL health probe to :443 does
	// not give a clean signal against a serving instance (incident 2026-06-17).
	// When QUILL_HEALTH_PORT is set we run a dedicated PLAINTEXT listener on a
	// separate port that returns 200 off the TLS path. It is unauthenticated
	// and exposes NO sensitive data — only liveness — so it is safe to bind in
	// the clear. GCP sets QUILL_HEALTH_PORT=8081 and points the LB health check
	// (and a firewall allow for 35.191.0.0/16,130.211.0.0/22) at it.
	if hp := strings.TrimSpace(os.Getenv("QUILL_HEALTH_PORT")); hp != "" {
		startHealthListener(hp)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go serveOne(ctx, conn, registry, br, tlsServer, deviceBlob, trGateway, byokSecrets)
	}
}

// startHealthListener binds a plaintext HTTP liveness endpoint on the given
// port and serves 200 on every path. It runs in its own goroutine so it never
// blocks the main serve loop. The endpoint returns no request-derived or
// secret data (no prompt logging, no attestation) — it exists solely so the
// load balancer can health-check the instance without traversing the TLS
// listener on :443.
func startHealthListener(port string) {
	hl, err := net.Listen("tcp", net.JoinHostPort("", port)) // #nosec G102 -- liveness-only, no sensitive data.
	if err != nil {
		fmt.Fprintf(os.Stderr, "health listener bind failed port=%s: %v\n", port, err)
		return
	}
	fmt.Fprintf(os.Stderr, "health listener up port=%s\n", port)
	go func() {
		srv := &http.Server{
			ReadHeaderTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "ok\n")
			}),
		}
		if err := srv.Serve(hl); err != nil {
			fmt.Fprintf(os.Stderr, "health listener stopped port=%s: %v\n", port, err)
		}
	}()
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

	requestReader := bufio.NewReaderSize(conn, maxHTTPHeaderLineBytes+1)
	attestationCount := 0
	healthRequestCount := 0
	for serveOneRequest(ctx, conn, statsConn, requestReader, reg, br, deviceBlob, trGateway, byokSecrets, &attestationCount, &healthRequestCount) {
	}
}

func serveOneRequest(
	ctx context.Context,
	conn net.Conn,
	statsConn *responseStatsConn,
	requestReader *bufio.Reader,
	reg *auth.Registry,
	br llm.Client,
	deviceBlob []byte,
	trGateway *trustedrouter.Client,
	byokSecrets *byokcache.Cache,
	attestationCount *int,
	healthRequestCount *int,
) (keepAlive bool) {
	statsConn.ResetSnapshot()

	// Bound the TLS handshake + request read. The enclave terminates TLS
	// lazily (handshake deferred to the first read in readRequest), so a bare
	// TCP connection that establishes and sends NO ClientHello — e.g. an L4
	// load-balancer health probe — would otherwise pin this goroutine on a
	// blocking handshake read forever, never reaching the deferred Close. That
	// leaves the probe connection half-open instead of cleanly closed, which a
	// GCP passthrough-NLB TCP health check reads as unhealthy. A deadline makes
	// such probes time out and close cleanly (FIN). Cleared once the request is
	// read so streaming responses are never truncated.
	_ = conn.SetReadDeadline(time.Now().Add(requestReadTimeout))

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

	method, path, bearer, idempotencyKey, attribution, body, err := readRequest(requestReader)
	processingStartedAt := time.Now()
	// Request (and its TLS handshake) is fully read; drop the deadline so a
	// long-running streamed response is never cut off.
	_ = conn.SetReadDeadline(time.Time{})
	requestMethod = method
	if err != nil {
		if closeWithoutReadErrorResponse(err) {
			return
		}
		if errors.Is(err, errBodyTooLarge) {
			writeError(conn, 413, "request body too large")
			return
		}
		if errors.Is(err, errHeadersTooLarge) {
			writeError(conn, 431, "request headers too large")
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

	// Public liveness is deliberately computed entirely inside the enclave.
	// It does not authenticate, read storage, call the control plane, mint an
	// attestation token, or touch a provider. Keeping this tiny response alive
	// lets monitors measure a second request on the same TLS connection and
	// separates handshake cost from gateway processing without weakening the
	// prompt path.
	if method == "GET" && routePath == "/health" {
		(*healthRequestCount)++
		keepAlive = *healthRequestCount < maxHealthRequestsPerConn
		writeHealthResponse(conn, keepAlive, processingStartedAt)
		return keepAlive
	}

	// /attestation is anonymous because clients call it BEFORE pinning, so
	// requiring a bearer would defeat the purpose.
	// Trust binding still holds — the doc commits to the live TLS cert,
	// which only this enclave can speak.
	if method == "GET" && routePath == "/attestation" {
		leafDER := enclavetls.SelectedLeafDER(conn)
		exporter, err := statsConn.SelectedExporter()
		if leafDER != nil && (err != nil || len(exporter) == 0) {
			// G6 fail-closed: the RFC 9266 exporter is the mitigation. A TLS
			// attestation without that same-session binding is a genuine but
			// relayable token, so do not emit one.
			writeError(conn, 503, "attestation: exporter channel binding unavailable")
			return
		}
		if !serveAttestation(conn, leafDER, deviceBlob, nonce, exporter) {
			return
		}
		(*attestationCount)++
		// G6 pinning requires the prompt to ride the same TLS session whose
		// exporter was attested. Bound repeated attestations so keep-alive
		// cannot become an unbounded anonymous request loop.
		return *attestationCount < maxAttestationsPerConn
	}

	// Public SDK discovery belongs on the documented API origin. The enclave
	// relays only catalog metadata; prompt-bearing routes remain behind the
	// authentication gate below.
	if maybeServePublicModels(ctx, conn, method, routePath, trGateway) {
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

	if routePath == "/v1/embeddings" {
		if method != "POST" {
			writeError(conn, 404, "route not found")
			return
		}
		serveEmbeddings(ctx, conn, br, body, trGateway, trEnabled, bearer, byokSecrets, idempotencyKey, attribution, requestLogID)
		return
	}

	if maybeServeBatchRoute(ctx, conn, method, routePath, body, bearer) {
		return
	}

	if maybeServeVideoRoute(ctx, conn, method, routePath, body, trGateway, bearer, idempotencyKey) {
		return
	}

	// Agent budget introspection: GET /v1/key lets a key holder read its own
	// limits / per-window remaining / resets_at through the same attested
	// endpoint it sends inference to. The RAW BEARER NEVER LEAVES THE ENCLAVE:
	// KeyInfo calls the control plane's /internal/gateway/key keyed by the
	// key's lookup hash + the internal gateway token (same contract as
	// authorize). Relayed status is allowlisted so a surprise 1xx/3xx can't
	// confuse an OpenAI-style client.
	if routePath == "/v1/key" {
		if method != "GET" || !trEnabled {
			writeError(conn, 404, "route not found")
			return
		}
		status, keyBody, err := trGateway.KeyInfo(ctx, bearer)
		if err != nil {
			writeError(conn, 502, "control plane unavailable")
			return
		}
		// Only relay the control-plane body for an EXPECTED status. An
		// unexpected status (including a raw 502) may carry an internal/proxy
		// body a key holder must not see, so drop it (codex).
		if safe, relay := allowlistKeyInfoStatus(status); relay {
			writeJSONResponse(conn, safe, keyBody)
		} else {
			writeError(conn, safe, "control plane unavailable")
		}
		return
	}

	// Native Anthropic Messages API. The internal pipeline is already
	// Anthropic-shaped, so this route passes content through verbatim and
	// relays the provider's native SSE back out — the surface Claude Code
	// and the Anthropic SDKs use via ANTHROPIC_BASE_URL.
	if routePath == "/v1/messages" {
		if method != "POST" {
			writeAnthropicError(conn, 404, "route not found")
			return
		}
		serveMessages(ctx, conn, br, body, trGateway, byokSecrets, bearer, idempotencyKey, requestLogID, attribution)
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
			if message, ok := tagValidationMessage(err); ok {
				writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
				return
			}
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
		req.NormalizeMaxTokens()
		originalInput = responsesReq.Input
	} else if routePath == "/v1/chat/completions" {
		if method != "POST" {
			writeError(conn, 404, "route not found")
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			if message, ok := tagValidationMessage(err); ok {
				writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
				return
			}
			writeError(conn, 400, "invalid JSON")
			return
		}
		req.NormalizeMaxTokens()
		originalInput = req.Messages
	} else {
		writeError(conn, 404, "route not found")
		return
	}
	req.IdempotencyKey = idempotencyKey
	applyAttributionHeaders(&req, attribution)
	if err := validateOrObserveRequestMetadata(&req, requestLogID); err != nil {
		if message, ok := tagValidationMessage(err); ok {
			writeOpenAIError(conn, 400, message, "invalid_request_error", "invalid_tags", "tags")
			return
		}
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "invalid_request_metadata", "")
		return
	}
	if err := adapter.RejectUnsupportedN(&req); err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeAdapterOpenAIError(conn, aerr)
			return
		}
		writeError(conn, 400, "invalid request")
		return
	}

	if routeType == "responses" && maybeServeResponsesWebSearch(
		ctx, conn, &req, br, trGateway, byokSecrets, bearer, requestLogID,
	) {
		return
	}

	if routeType == "chat.completions" {
		if _, err := maybeResolveCustomModelForOrchestration(ctx, &req, trGateway, bearer, routeType); err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeError(conn, aerr.Status, aerr.Message)
				return
			}
			writeError(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "custom model resolution failed"))
			return
		}
	}

	if handled, err := maybeServeAdvisor(ctx, conn, br, &req, trGateway, byokSecrets, bearer, originalInput, requestLogID); handled {
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeError(conn, aerr.Status, aerr.Message)
				return
			}
			writeError(conn, 500, "advisor error")
		}
		return
	}

	if handled, err := maybeServeSubagent(ctx, conn, br, &req, trGateway, byokSecrets, bearer, originalInput, requestLogID); handled {
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeError(conn, aerr.Status, aerr.Message)
				return
			}
			writeError(conn, 500, "subagent error")
		}
		return
	}

	if handled, err := maybeServeFusion(ctx, conn, br, &req, trGateway, byokSecrets, bearer, originalInput, requestLogID); handled {
		if err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				writeError(conn, aerr.Status, aerr.Message)
				return
			}
			writeError(conn, 500, "fusion error")
		}
		return
	}

	var authorization *trustedrouter.Authorization
	var invokeOptions []llm.InvokeOptions
	requestStarted := time.Now()
	if trEnabled {
		authorization, err = trGateway.AuthorizeWithRoute(ctx, bearer, &req, routeType)
		if err != nil {
			writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"), "router", retryHeadersFromControlPlaneError(err))
			return
		}
		req.Models = nil
		invokeOptions, err = invokeOptionsForAuthorization(ctx, byokSecrets, authorization)
		if err != nil {
			_ = trGateway.Refund(ctx, authorization, 502, "byok_secret_error", time.Since(requestStarted).Seconds(), req.Metadata)
			writeError(conn, 502, "BYOK provider key unavailable")
			return
		}
		if len(invokeOptions) > 0 && invokeOptions[0].Model != "" {
			req.Model = invokeOptions[0].Model
		} else {
			req.Model = authorization.Model
		}
	}
	applyCustomModelPrompt(&req, authorization)
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
	if !req.Stream {
		if routeType == "responses" {
			serveResponsesNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, requestLogID)
			return
		}
		serveChatNonStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, requestLogID)
		return
	}
	serveStreaming(ctx, conn, br, &req, anthropicReq, invokeOptions, trGateway, authorization, byokSecrets, requestStarted, originalInput, routeType, requestLogID)
	return
}

func closeWithoutReadErrorResponse(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
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

func applyAttributionHeaders(req *types.OpenAIChatRequest, attribution requestAttributionHeaders) {
	if req == nil {
		return
	}
	if req.SessionID == "" {
		req.SessionID = attribution.SessionID
	}
	req.App = attribution.App
	req.HTTPReferer = attribution.HTTPReferer
	req.AppCategories = append([]string(nil), attribution.AppCategories...)
	req.OpenRouterMetadata = attribution.OpenRouterMetadata
}

func applyUsageAttribution(usage *trustedrouter.Usage, req *types.OpenAIChatRequest) {
	if usage == nil || req == nil {
		return
	}
	usage.App = req.App
	usage.HTTPReferer = req.HTTPReferer
	usage.AppCategories = append([]string(nil), req.AppCategories...)
}

func tagValidationMessage(err error) (string, bool) {
	var tagErr *types.TagValidationError
	if errors.As(err, &tagErr) {
		return tagErr.Error(), true
	}
	return "", false
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
		writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"), "router", retryHeadersFromControlPlaneError(err))
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

func responseTextConfig(req *types.OpenAIChatRequest) map[string]any {
	if req == nil || req.Response == nil {
		return nil
	}
	return req.Response.Text
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
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID, true, true)
	result, err := adapter.CollectAnthropicText(pr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.responses_collect_failed model=%q err=%v\n", req.Model, err)
		// Surface the real upstream status+message instead of an opaque 502.
		status, message := upstreamErrorResponse(err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, status, failureReason(err), time.Since(requestStarted).Seconds(), req.Metadata)
		}
		writeClassifiedOpenAIError(conn, status, message, err)
		return
	}
	if len(result.ToolCalls) == 0 {
		if normalized, err := adapter.NormalizeResponsesStructuredOutput(result.Text, responseTextConfig(req)); err != nil {
			var aerr *adapter.AdapterError
			if asAdapterErr(err, &aerr) {
				fmt.Fprintf(os.Stderr, "enclave.responses_structured_output_failed model=%q context=%q\n", req.Model, aerr.Context)
				if trGateway != nil && trGateway.Enabled() {
					_ = trGateway.Refund(ctx, authorization, aerr.Status, "provider_structured_output_error", time.Since(requestStarted).Seconds(), req.Metadata)
				}
				writeAdapterOpenAIError(conn, aerr)
				return
			}
			if trGateway != nil && trGateway.Enabled() {
				_ = trGateway.Refund(ctx, authorization, 502, "provider_structured_output_error", time.Since(requestStarted).Seconds(), req.Metadata)
			}
			writeSpentProviderError(conn, 502, "provider structured output error")
			return
		} else {
			result.Text = normalized
		}
	}
	outputForUsage := adapter.ResponsesOutputForUsage(result)
	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(outputForUsage),
	)
	selectedModel := selectedRoute.Model(req.Model, authorization)
	selectedEndpoint := selectedRoute.Endpoint("", authorization)
	if selectedModel != "" {
		req.Model = selectedModel
	}
	responseModel := customModelResponseModel(req.Model, authorization)
	var body bytes.Buffer
	if err := adapter.WriteResponsesResponse(&body, requestID, responseModel, result.Text, result.ToolCalls, inputTokens, outputTokens, result.Usage, time.Now().Unix(), responseTextConfig(req), req.Response); err != nil {
		writeSpentError(conn, 500, "responses encoding error")
		return
	}
	usage := trustedrouter.Usage{
		RequestID:         requestID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: 0,
		UsageEstimated:    usageEstimated,
		FinishReason:      result.FinishReason,
		Streamed:          false,
		RouteType:         "responses",
		SelectedModel:     selectedModel,
		SelectedEndpoint:  selectedEndpoint,
		User:              req.User,
		SessionID:         req.SessionID,
		Trace:             req.Trace,
		Metadata:          req.Metadata,
		ServiceTier:       requestedServiceTierForSettlement(req),
	}
	applyUsageAttribution(&usage, req)
	applyCacheUsage(&usage, result)
	settlement, err := settleAndBroadcast(ctx, trGateway, authorization, secretCache, usage, req, originalInput, outputForUsage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.responses_settle_failed model=%q err=%v\n", req.Model, err)
		writeSpentError(conn, 502, "settlement failed")
		return
	}
	annotatedBody, err := annotateSettledResponseMetadata(body.Bytes(), authorization, settlement, selectedRoute, invokeOptions, result, req.OpenRouterMetadata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.responses_metadata_failed model=%q err=%v\n", req.Model, err)
		writeSpentError(conn, 500, "responses encoding error")
		return
	}
	writeJSONResponse(conn, 200, annotatedBody)
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
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID, true, true)
	result, err := adapter.CollectAnthropicText(pr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.chat_collect_failed model=%q err=%v\n", req.Model, err)
		// Surface the real upstream status+message (e.g. a 400 "max_tokens is too
		// large for this model") instead of an opaque 502, matching the streaming
		// path. upstreamErrorResponse falls back to 502 if it can't classify.
		status, message := upstreamErrorResponse(err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, status, failureReason(err), time.Since(requestStarted).Seconds(), req.Metadata)
		}
		writeClassifiedOpenAIError(conn, status, message, err)
		return
	}
	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(result.Text),
	)
	selectedModel := selectedRoute.Model(req.Model, authorization)
	selectedEndpoint := selectedRoute.Endpoint("", authorization)
	if selectedModel != "" {
		req.Model = selectedModel
	}
	responseModel := customModelResponseModel(req.Model, authorization)
	var body bytes.Buffer
	if err := adapter.WriteChatCompletionResponse(&body, requestID, responseModel, result.Text, adapter.JoinThinking(result.Thinking), result.ToolCalls, inputTokens, outputTokens, result.Usage, time.Now().Unix(), result.FinishReason); err != nil {
		writeSpentError(conn, 500, "chat completion encoding error")
		return
	}
	usage := trustedrouter.Usage{
		RequestID:         requestID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: 0,
		UsageEstimated:    usageEstimated,
		FinishReason:      result.FinishReason,
		Streamed:          false,
		RouteType:         "chat.completions",
		SelectedModel:     selectedModel,
		SelectedEndpoint:  selectedEndpoint,
		User:              req.User,
		SessionID:         req.SessionID,
		Trace:             req.Trace,
		Metadata:          req.Metadata,
		ServiceTier:       requestedServiceTierForSettlement(req),
	}
	applyUsageAttribution(&usage, req)
	applyCacheUsage(&usage, result)
	settlement, err := settleAndBroadcast(ctx, trGateway, authorization, secretCache, usage, req, originalInput, result.Text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.chat_settle_failed model=%q err=%v\n", req.Model, err)
		writeSpentError(conn, 502, "settlement failed")
		return
	}
	annotatedBody, err := annotateSettledResponseMetadata(body.Bytes(), authorization, settlement, selectedRoute, invokeOptions, result, req.OpenRouterMetadata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.chat_metadata_failed model=%q err=%v\n", req.Model, err)
		writeSpentError(conn, 500, "chat completion encoding error")
		return
	}
	writeJSONResponse(conn, 200, annotatedBody)
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
	providerReq := *req
	go func() {
		defer close(providerDone)
		invokeProviderStream(ctx, br, &providerReq, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID, true, true)
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
	responseModel := customModelResponseModel(req.Model, authorization)
	var routerMetadata map[string]any
	if req.OpenRouterMetadata {
		routerMetadata = openRouterRoutingMetadata(authorization, selectedRoute)
		if routeType == "responses" {
			if req.Response == nil {
				req.Response = &types.ResponseRequestMeta{}
			}
			req.Response.OpenRouterMetadata = routerMetadata
		}
	}
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		_ = pr.Close()
		return
	}

	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)
	streamW := io.Writer(statsW)
	var batchW io.WriteCloser
	if routeType == "chat.completions" {
		batchW = newSSEBatchWriter(statsW)
		streamW = batchW
	}

	var result adapter.StreamResult
	var err error
	if routeType == "responses" {
		result, err = adapter.TransformResponsesStream(pr, statsW, requestID, responseModel, trustedrouter.EstimateInputTokens(req), responseTextConfig(req), req.Response)
	} else {
		result, err = adapter.TransformStreamCaptureWithRouterMetadata(pr, streamW, requestID, responseModel, chatIncludeUsage(req), routerMetadata)
	}
	if batchW != nil {
		if closeErr := batchW.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.transform_stream_failed model=%q err=%v\n", req.Model, err)
		status, _ := upstreamErrorResponse(err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, status, failureReason(err), time.Since(requestStarted).Seconds(), req.Metadata)
		}
		if routeType == "responses" || statsW.BytesWritten() == 0 {
			_ = writeStreamingProviderError(statsW, routeType, requestID, responseModel, err)
		}
		return
	}
	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(adapter.ResponsesOutputForUsage(result)),
	)
	usage := trustedrouter.Usage{
		RequestID:         requestID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: statsW.FirstWriteSeconds(requestStarted),
		UsageEstimated:    usageEstimated,
		FinishReason:      result.FinishReason,
		Streamed:          true,
		RouteType:         routeType,
		SelectedModel:     selectedRoute.Model(req.Model, authorization),
		SelectedEndpoint:  selectedRoute.Endpoint("", authorization),
		User:              req.User,
		SessionID:         req.SessionID,
		Trace:             req.Trace,
		Metadata:          req.Metadata,
		ServiceTier:       requestedServiceTierForSettlement(req),
	}
	applyUsageAttribution(&usage, req)
	applyCacheUsage(&usage, result)
	if _, err := settleAndBroadcast(
		ctx,
		trGateway,
		authorization,
		secretCache,
		usage,
		req,
		originalInput,
		adapter.ResponsesOutputForUsage(result),
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
			usage:         usage,
			requestLogID:  requestLogID,
		})
	}
}

func serveMessages(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	body []byte,
	trGateway *trustedrouter.Client,
	byokSecrets *byokcache.Cache,
	bearer string,
	idempotencyKey string,
	requestLogID string,
	attribution requestAttributionHeaders,
) {
	var native adapter.AnthropicNativeRequest
	if err := json.Unmarshal(body, &native); err != nil {
		if message, ok := tagValidationMessage(err); ok {
			writeAnthropicError(conn, 400, message)
			return
		}
		writeAnthropicError(conn, 400, "invalid JSON")
		return
	}
	req := adapter.MessagesToChatShim(&native)
	req.IdempotencyKey = idempotencyKey
	applyAttributionHeaders(req, attribution)
	if err := validateOrObserveRequestMetadata(req, requestLogID); err != nil {
		writeAnthropicError(conn, 400, err.Error())
		return
	}
	// Orchestration primitives currently emit OpenAI/Responses envelopes. Do
	// not forward their public aliases to the control-plane route selector: it
	// must fail closed rather than silently reducing an orchestration request to
	// one model, and the resulting intentional 501 used to look like an internal
	// billing outage. Reject at the public endpoint before authorization so no
	// hold is created and the caller receives the native Messages error shape.
	if isOrchestrationModel(req.Model) || isGenericAdvisorPrimitive(req.Model) {
		fmt.Fprintf(os.Stderr,
			"enclave.messages_orchestration_unsupported request_log_id=%q model=%q\n",
			requestLogID,
			req.Model,
		)
		writeAnthropicError(conn, 501, "TrustedRouter orchestration models are not supported by the Anthropic Messages API; use /v1/chat/completions or /v1/responses")
		return
	}
	if err := adapter.RejectUnsupportedN(req); err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeAnthropicError(conn, aerr.Status, aerr.Message)
			return
		}
		writeAnthropicError(conn, 400, "invalid request")
		return
	}
	anthropicReq, err := adapter.MessagesToAnthropic(&native)
	if err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeAnthropicError(conn, aerr.Status, aerr.Message)
			return
		}
		writeAnthropicError(conn, 400, "invalid messages request")
		return
	}

	requestStarted := time.Now()
	trEnabled := trGateway != nil && trGateway.Enabled()
	var authorization *trustedrouter.Authorization
	var invokeOptions []llm.InvokeOptions
	if trEnabled {
		authorization, err = trGateway.AuthorizeWithRoute(ctx, bearer, req, "messages")
		if err != nil {
			writeAnthropicErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"), "router", retryHeadersFromControlPlaneError(err))
			return
		}
		invokeOptions, err = invokeOptionsForAuthorization(ctx, byokSecrets, authorization)
		if err != nil {
			_ = trGateway.Refund(ctx, authorization, 502, "byok_secret_error", time.Since(requestStarted).Seconds(), req.Metadata)
			writeAnthropicError(conn, 502, "BYOK provider key unavailable")
			return
		}
		if len(invokeOptions) > 0 && invokeOptions[0].Model != "" {
			req.Model = invokeOptions[0].Model
		} else {
			req.Model = authorization.Model
		}
	}
	applyCustomModelPromptToMessages(req, anthropicReq, authorization)

	messageID := newMessageID()
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()

	if !native.Stream {
		go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trEnabled, authorization, selectedRoute, requestLogID, true, true)
		result, err := adapter.CollectAnthropicText(pr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclave.messages_collect_failed model=%q err=%v\n", req.Model, err)
			status, message := upstreamErrorResponse(err)
			if trEnabled {
				_ = trGateway.Refund(ctx, authorization, status, failureReason(err), time.Since(requestStarted).Seconds(), req.Metadata)
			}
			writeClassifiedAnthropicError(conn, status, message, err)
			return
		}
		inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
			result,
			trustedrouter.EstimateInputTokens(req),
			trustedrouter.EstimateOutputTokens(result.Text),
		)
		selectedModel := selectedRoute.Model(req.Model, authorization)
		selectedEndpoint := selectedRoute.Endpoint("", authorization)
		if selectedModel != "" {
			req.Model = selectedModel
		}
		responseModel := customModelResponseModel(req.Model, authorization)
		var envelope bytes.Buffer
		if err := adapter.WriteMessagesResponse(&envelope, messageID, responseModel, result, inputTokens, outputTokens); err != nil {
			writeAnthropicError(conn, 500, "messages encoding error")
			return
		}
		usage := trustedrouter.Usage{
			RequestID:        messageID,
			InputTokens:      inputTokens,
			OutputTokens:     outputTokens,
			ElapsedSeconds:   maxDurationSeconds(time.Since(requestStarted), 0.001),
			UsageEstimated:   usageEstimated,
			FinishReason:     result.FinishReason,
			Streamed:         false,
			RouteType:        "messages",
			SelectedModel:    selectedModel,
			SelectedEndpoint: selectedEndpoint,
			Metadata:         req.Metadata,
		}
		applyUsageAttribution(&usage, req)
		applyCacheUsage(&usage, result)
		settlement, err := settleAndBroadcast(ctx, trGateway, authorization, byokSecrets, usage, req, native.Messages, result.Text)
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclave.messages_settle_failed model=%q err=%v\n", req.Model, err)
			writeAnthropicError(conn, 502, "settlement failed")
			return
		}
		responseBody, err := annotateBatchSettlementOnlyUsage(ctx, envelope.Bytes(), settlement)
		if err != nil {
			writeAnthropicError(conn, 500, "messages encoding error")
			return
		}
		writeJSONResponse(conn, 200, responseBody)
		return
	}

	providerDone := make(chan struct{})
	providerReq := *req
	go func() {
		defer close(providerDone)
		invokeProviderStream(ctx, br, &providerReq, anthropicReq, pw, invokeOptions, trEnabled, authorization, selectedRoute, requestLogID, true, true)
	}()
	if trEnabled && len(invokeOptions) > 1 {
		select {
		case <-selectedRoute.Ready():
		case <-providerDone:
		}
	} else if len(invokeOptions) > 0 {
		selectedRoute.Select(invokeOptions[0])
	}
	if streamModel := selectedRoute.Model(req.Model, authorization); streamModel != "" {
		req.Model = streamModel
	}
	responseModel := customModelResponseModel(req.Model, authorization)
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		_ = pr.Close()
		return
	}
	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)

	result, err := adapter.RelayAnthropicStream(pr, statsW, messageID, responseModel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.messages_relay_failed model=%q err=%v\n", req.Model, err)
		status, _ := upstreamErrorResponse(err)
		if trEnabled {
			_ = trGateway.Refund(ctx, authorization, status, failureReason(err), time.Since(requestStarted).Seconds(), req.Metadata)
		}
		if statsW.BytesWritten() == 0 {
			_, message := upstreamErrorResponse(err)
			_ = writeAnthropicStreamError(statsW, message)
		}
		return
	}
	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(result.Text),
	)
	usage := trustedrouter.Usage{
		RequestID:         messageID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: statsW.FirstWriteSeconds(requestStarted),
		UsageEstimated:    usageEstimated,
		FinishReason:      result.FinishReason,
		Streamed:          true,
		RouteType:         "messages",
		SelectedModel:     selectedRoute.Model(req.Model, authorization),
		SelectedEndpoint:  selectedRoute.Endpoint("", authorization),
		Metadata:          req.Metadata,
	}
	applyUsageAttribution(&usage, req)
	applyCacheUsage(&usage, result)
	if _, err := settleAndBroadcast(ctx, trGateway, authorization, byokSecrets, usage, req, native.Messages, result.Text); err != nil {
		fmt.Fprintf(os.Stderr,
			"enclave.messages_stream_settle_failed request_log_id=%q request_id=%q model=%q err=%v\n",
			requestLogID, messageID, req.Model, err,
		)
		settlementRetries.Enqueue(settlementRetryJob{
			trGateway:     trGateway,
			authorization: authorization,
			usage:         usage,
			requestLogID:  requestLogID,
		})
	}
}

// chatIncludeUsage reports whether the client asked for the OpenAI
// stream_options.include_usage final chunk on a chat-completions stream.
func chatIncludeUsage(req *types.OpenAIChatRequest) bool {
	return req != nil && req.StreamOptions != nil && req.StreamOptions.IncludeUsage
}

func resolvedProviderForRequest(req *types.OpenAIChatRequest, options []llm.InvokeOptions, authorization *trustedrouter.Authorization) string {
	if len(options) > 0 && options[0].Provider != "" {
		return options[0].Provider
	}
	if authorization != nil && authorization.Provider != "" {
		return authorization.Provider
	}
	return ""
}

func resolvedModelForRequest(req *types.OpenAIChatRequest, options []llm.InvokeOptions, authorization *trustedrouter.Authorization) string {
	if len(options) > 0 && options[0].Model != "" {
		return options[0].Model
	}
	if req != nil && req.Model != "" {
		return req.Model
	}
	if authorization != nil {
		return authorization.Model
	}
	return ""
}

// realOrEstimatedTokens prefers the provider-reported usage captured from
// the stream (adapter.StreamResult.Usage) and falls back to the chars/4
// estimates the gateway has always used. Returns (input, output,
// usageEstimated-for-settlement). Output is the signal: providers always
// report both sides together, but if input is somehow missing we estimate
// it and still flag the settlement as estimated.
// applyCacheUsage copies provider-reported reasoning and prompt-cache token
// counts into the settlement usage record (visibility only — pricing unchanged).
func applyCacheUsage(usage *trustedrouter.Usage, result adapter.StreamResult) {
	if result.Usage == nil {
		return
	}
	usage.ReasoningTokens = result.Usage.ReasoningTokens
	usage.CacheReadInputTokens = result.Usage.CacheReadInputTokens
	usage.CacheCreationInputTokens = result.Usage.CacheCreationInputTokens
	if tier, ok := canonicalServiceTier(result.Usage.ServiceTier); ok {
		usage.ServiceTier = tier
	}
}

// canonicalServiceTier maps a provider's reported tier onto the vocabulary
// settlement accepts, reporting whether it recognized the value at all.
//
// Providers disagree on the name of the ordinary tier: Anthropic reports
// "standard", OpenAI reports "default". They price the same.
//
// An UNRECOGNIZED tier is dropped rather than forwarded. Settlement runs after
// the upstream call has been made and paid for, so forwarding a word the
// control plane rejects costs TrustedRouter the provider spend AND fails the
// caller's request — which is exactly what "standard" did to every Anthropic
// request. Dropping it leaves the already-validated requested tier in place.
//
// Cheaper tiers (Anthropic "batch", OpenAI "flex"/"scale") are deliberately
// NOT mapped to "default": settling one of those at the default rate would
// overcharge the customer.
func canonicalServiceTier(reported string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(reported)) {
	case "standard", "default":
		return "default", true
	case "priority":
		return "priority", true
	default:
		return "", false
	}
}

func requestedServiceTierForSettlement(req *types.OpenAIChatRequest) string {
	if req == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(req.ServiceTier)) {
	case "priority":
		// OpenAI documents the actual tier in every response when requested.
		// If an upstream omits it, retain the requested priority tier rather
		// than silently undercharging an operator-funded request.
		return "priority"
	case "auto":
		// Auto may be downgraded. Missing provider metadata is settled at the
		// customer-favorable standard rate; a reported actual tier overrides it.
		return "default"
	case "default":
		return "default"
	default:
		return ""
	}
}

func realOrEstimatedTokens(result adapter.StreamResult, estimatedInput, estimatedOutput int) (int, int, bool) {
	if result.Usage == nil || result.Usage.OutputTokens <= 0 {
		return estimatedInput, estimatedOutput, true
	}
	// input_tokens == 0 is a REAL count only for an Anthropic full prompt-cache
	// hit: the convention is exclusive-of-cache (InputExcludesCache) AND the
	// prompt is actually accounted under cache_read/creation. In that case the
	// zero must be kept — substituting the chars/4 estimate would settle billing
	// on an inflated uncached count and double-count prompt_tokens once the
	// OpenAI usage folds cache back in. Otherwise a zero is a MISSING count and
	// must fall back to the estimate: non-Anthropic providers report a
	// cache-inclusive prompt (a zero there is missing), and even an Anthropic
	// stream with no cache tokens leaves the prompt unaccounted.
	hasCacheTokens := result.Usage.CacheReadInputTokens > 0 || result.Usage.CacheCreationInputTokens > 0
	if result.Usage.InputTokens <= 0 && !(result.Usage.InputExcludesCache && hasCacheTokens) {
		return estimatedInput, result.Usage.OutputTokens, true
	}
	return result.Usage.InputTokens, result.Usage.OutputTokens, false
}

func maybeStartAttestSidecar() {
	const sidecarPath = "/attest-sidecar"
	if os.Getenv("QUILL_DISABLE_ATTEST_SIDECAR") == "1" {
		fmt.Fprintln(os.Stderr, "attest_sidecar.skipped reason=disabled_env")
		return
	}
	info, err := os.Stat(sidecarPath)
	if err != nil {
		// Not packaged — log and continue serving other providers. Every
		// Tinfoil route will refuse before provider invocation.
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
	// Reap the child if it ever exits so it doesn't become a zombie. We
	// don't restart it here; the per-request sidecar status check makes
	// Tinfoil fail closed immediately, while other providers keep serving.
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "attest_sidecar.exited err=%q pid=%d\n", err.Error(), cmd.Process.Pid)
		} else {
			fmt.Fprintf(os.Stderr, "attest_sidecar.exited ok pid=%d\n", cmd.Process.Pid)
		}
	}()
}

// dns01Provider selects the DNS-01 challenge publisher.
//
// Cloud DNS when a project and managed zone are configured, Cloudflare (nil,
// the DNS01Config default) otherwise. trustedrouter.com is served by Cloud DNS,
// so the Cloudflare-only renewer could never touch the zone that actually
// matters — it looked configured and could not have worked.
func dns01Provider() enclavetls.DNS01Provider {
	project := strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_GCP_PROJECT"))
	zone := strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_MANAGED_ZONE"))
	if project == "" || zone == "" {
		return nil
	}
	return enclavetls.NewCloudDNSProvider(project, zone, enclavetls.NewDNS01HTTPClient())
}
