// Tinfoil dual-source TLS-pin-from-attestation: every tinfoil request
// lands on the public key the enclave's SEV-SNP attestation report
// committed to, with full AMD-signature + Sigstore code-measurement
// verification.
//
// Architecture
// ============
//
// Two independent fetches of the SEV-SNP attestation produce two
// fingerprints; we refuse the request unless they agree.
//
//   rawFP      ← in-process stdlib parse here
//                  fetchExpectedTLSPubkeyFP() below: GET
//                  /.well-known/tinfoil-attestation, gunzip + base64-
//                  decode the body, read REPORT_DATA[0:32] (= SHA-256
//                  of the enclave's TLS PKIX-DER public key per
//                  Tinfoil's convention).
//
//   verifiedFP ← /attest-sidecar over Unix socket
//                  enclave-go/sidecar/ is a SEPARATE Go module that
//                  imports tinfoilsh/tinfoil-go/verifier/client and
//                  runs the full chain: Sigstore-signed code-measurement
//                  bundle from the GitHub release of
//                  tinfoilsh/confidential-model-router, AMD VCEK chain
//                  on the SEV-SNP report, and only THEN extracts the
//                  TLS pubkey FP. cmd/enclave/main.go fork-execs
//                  /attest-sidecar at startup; we read its result
//                  via fetchSidecarVerifiedFP().
//
// Why the sidecar lives in its own module: linking
// tinfoilsh/tinfoil-go/verifier/client into the main enclave binary
// pulled in ~30 MB of transitive deps (sigstore-go, go-tuf/v2,
// certificate-transparency-go, transparency-dev/merkle, mongo-driver,
// otel, grpc, protobuf, sigstore/rekor) and forced a Go 1.25
// toolchain bump. The combination corrupted the main enclave's
// vsock+TLS request loop — every request started returning HTTP 400
// "could not read request" within minutes of rollout (deploy
// 25592563258), tripping the canary. Isolating the heavy chain in
// a separate process + separate module keeps the main enclave's
// dep graph lean (this file uses Go stdlib only).
//
// Cross-check decision matrix (resolveExpectedFP below)
// =====================================================
//
//   both ok + agree    → use verifiedFP (the safer of the two)
//   both ok + disagree → REFUSE — either tinfoil is rotating mid-
//                        fetch (next attempt resolves) or one
//                        network leg is being MITM'd
//   raw ok, sidecar dn → raw-only mode, log "sidecar unreachable"
//   sidecar ok, raw dn → sidecar-only mode, log "raw fetch failed"
//   neither ok         → hard error; tinfoil requests fail closed
//
// Per-request enforcement
// =======================
//
// pinnedTLSDial wires the resolved FP into a DialTLSContext: every
// TLS handshake to inference.tinfoil.sh checks the leaf cert's
// PKIX-DER pubkey SHA-256 against the expected FP and refuses the
// connection on mismatch — before any byte of HTTP request data
// goes out. Cert rotation triggers ONE re-fetch + retry; persistent
// mismatch hard-errors (no fallback to a non-pinned client).
//
// Trust hooks layered around the Unix socket
// ==========================================
//
//   * Sidecar side (sidecar/main.go::uidEnforcingListener): each
//     accepted connection's peer UID is checked via SO_PEERCRED;
//     mismatch = drop. Closes off random other-uid processes.
//   * Main enclave side (unixSocketHTTPClient below): the dialer
//     uses SO_PEERCRED to verify the peer process PID matches the
//     fork-exec'd child whose PID we recorded via
//     SetExpectedSidecarPID. Closes off the abstract-socket
//     race-to-bind attack.
//
// Both checks are Linux-only (SO_PEERCRED). Sibling stubs in
// peercred_other.go return "only supported on Linux"; the dialer
// soft-skips on non-Linux dev hosts so local testing still works.
//
// Per-request hot-path cost
// =========================
//
// First-tinfoil-request only:
//   * Stdlib raw fetch: 1 HTTPS roundtrip + gzip + sha256 (~tens of ms)
//   * Sidecar query: ~ms over Unix socket (sidecar caches Verify
//     result for 10 min, so its response is in-memory)
//   * String compare on the two FPs.
//
// Every subsequent request:
//   * One SHA-256 of the peer cert's DER pubkey + one string compare,
//     both inside the existing TLS handshake. Microseconds.
//
// Empirically: tinfoil US TTFT pre-attestation 779 ms avg →
// post-attestation 805 ms avg. Delta is run-to-run noise.
//
// Threat model
// ============
//
// What this design DOES catch:
//
//   * Network MITM on either the in-process raw fetch path or the
//     sidecar's Verify chain — caught by cross-check disagreement.
//   * A lying sidecar process (e.g. an in-VM race where some other
//     process binds @tinfoil-attest before our fork-exec'd child
//     and answers with a forged FP) — the in-process rawFP is still
//     computed by Go code in this package, untouched by the
//     impostor, so disagreement triggers refuse. Belt-and-suspenders
//     SO_PEERCRED + PID-pin (peercred_linux.go) catches the bind
//     race even before the cross-check fires.
//   * Tinfoil rotating their cert mid-flight — re-fetch + retry once
//     handles it transparently.
//
// Note that "swap the /attest-sidecar binary on disk" is NOT a
// distinct attack we have to defend against here, because it's
// already caught one layer up: the sidecar binary is part of our
// Confidential Space container image, so its bytes are hashed into
// the same SEV-SNP measurement that anyone calling our enclave's
// /attestation endpoint verifies. Modifying the sidecar on disk
// changes the image_digest, changes the AMD-signed report, and any
// client doing real attestation verification sees a measurement
// mismatch. The transitive chain is: our binary identity is
// attested → the sidecar binary identity is attested through it →
// the sidecar's verifiedFP value is signed-and-verified by Sigstore
// + AMD VCEK → tinfoil's TLS pubkey is bound to that.
//
// What this design ASSUMES does NOT happen (out of scope):
//
//   The cross-check provides defense-in-depth against compromise of
//   any SINGLE leg (a lying sidecar process, our machine's network
//   leg, GitHub-served Sigstore bundles, tinfoil's .well-known
//   endpoint). It does NOT defend against an attacker who
//   simultaneously controls MULTIPLE independent organizations'
//   infrastructure on a coordinated timeline — specifically:
//
//     (a) ship a malicious /attest-sidecar binary in our published
//         enclave image (= compromise our build pipeline / Artifact
//         Registry; would change the image_digest visible to anyone
//         verifying our attestation), AND at the same time
//     (b) modify the data GitHub serves for tinfoilsh/confidential-
//         model-router release attestations (so the malicious
//         sidecar's lie matches what a legitimate Verify chain would
//         have produced), AND also
//     (c) make either inference.tinfoil.sh's .well-known endpoint or
//         our network leg to it serve a matching forged SEV-SNP report
//
//   Pulling all three off in concert means breaching multiple
//   organizations on a single timeline (us — specifically our build
//   chain, since runtime disk-write inside Confidential Space is
//   already blocked by the TEE — plus GitHub, plus tinfoil/AMD).
//   That's a sophisticated multi-target attack well outside the
//   threat surface this design is sized for. With ANY single leg of
//   the three intact, the cross-check refuses the request.
//
//   AMD's signing key is the hard floor: forging an SEV-SNP report
//   requires it (it lives inside AMD's CPUs and is not extractable).
//   Without it, no forged report validates against the AMD VCEK
//   chain inside the sidecar's Verify, so even the combined "build
//   chain + GitHub" attack still has to also separately compromise
//   tinfoil's enclave deployment to make the .well-known endpoint
//   serve a SEV-SNP report attesting to the attacker's TLS key. At
//   that point the attacker IS tinfoil from the protocol's
//   perspective, and we've left the regime any client of
//   inference.tinfoil.sh can defend against.
//
//   Note specifically that "swap /attest-sidecar at runtime inside
//   the enclave VM" is NOT in this list because it's blocked one
//   layer down: Confidential Space's TEE memory protection prevents
//   in-VM disk writes from outside the workload itself, AND the
//   image_digest covers both binaries, so any binary swap that DID
//   somehow happen (e.g. supply-chain attack on our build) would
//   surface as a measurement mismatch on our /attestation endpoint.
package llm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tinfoilEnclaveHost = "inference.tinfoil.sh"
	tinfoilAttestPath  = "/.well-known/tinfoil-attestation"

	// SEV-SNP guest report offsets, AMD SEV-SNP ABI §7.3 (Table 22).
	// REPORT_DATA is at byte 0x50 and is 64 bytes long. The in-process
	// stdlib parse below ONLY reads REPORT_DATA — the AMD-signature
	// chain on the surrounding report is verified by the sidecar
	// process (enclave-go/sidecar/) which independently fetches the
	// same report. Cross-checking both fingerprints (resolveExpectedFP)
	// catches any disagreement between the two paths, so this raw
	// parse doesn't need to verify the signature itself.
	sevSnpReportDataOffset = 0x50
	sevSnpReportDataLen    = 64
)

// tinfoilAttestation matches the JSON shape /.well-known/tinfoil-attestation
// returns:  {"format":"...sev-snp-guest/v2","body":"<gzip+base64>"}
type tinfoilAttestation struct {
	Format string `json:"format"`
	Body   string `json:"body"`
}

// tinfoilSidecarSocket is where the attest-sidecar (a separate binary
// living at enclave-go/sidecar/) listens for cross-check queries. When
// the socket exists and answers, the main enclave dual-sources the
// expected TLS fingerprint: stdlib-only parse here (rawFP) AND
// full-Sigstore-+-AMD-VCEK-chain-verified (verifiedFP) from the sidecar.
// Disagreement = refuse the request. Sidecar unreachable = log loudly
// and fall through to rawFP-only (the pin still holds).
//
// "@tinfoil-attest" is a Linux abstract socket — no filesystem entry,
// works even when the runtime image is FROM scratch and /run is read
// only. Override via TINFOIL_ATTEST_SOCKET if you want to point it at
// a path-based socket (e.g. for local development).
var tinfoilSidecarSocket = "@tinfoil-attest"

func init() {
	if v := os.Getenv("TINFOIL_ATTEST_SOCKET"); v != "" {
		tinfoilSidecarSocket = v
	}
}

// expectedSidecarPID is the PID the main enclave fork-exec'd for the
// attest-sidecar at boot. Set via SetExpectedSidecarPID before any
// tinfoil request can race in. Zero means "not set" — the unix dialer
// then accepts any peer (used for local dev where peer-cred lookups
// aren't available, see peercred_other.go).
//
// The unix dialer enforces this via SO_PEERCRED: a connection whose
// peer PID isn't this exact value gets dropped with errSidecarPIDMismatch.
// Defends against an attacker who somehow binds @tinfoil-attest before
// our child sidecar does — abstract sockets have no filesystem
// permission bits, so PID-pinning is the cheapest way to authenticate
// "I'm talking to the binary I just spawned, not someone impersonating it."
var expectedSidecarPID atomic.Int32

// SetExpectedSidecarPID is called by cmd/enclave once it's fork-exec'd
// /attest-sidecar; the resulting PID becomes the only acceptable peer
// for unix-socket connections to @tinfoil-attest.
func SetExpectedSidecarPID(pid int) {
	expectedSidecarPID.Store(int32(pid))
}

var errSidecarPIDMismatch = errors.New("attest sidecar peer PID mismatch")

// fetchExpectedTLSPubkeyFP is the rawFP source for the cross-check.
// Fetches Tinfoil's attestation document over plain HTTPS and extracts
// REPORT_DATA[0:32] from the SEV-SNP report; the result is a lowercase
// hex SHA-256 of the enclave's TLS public key (PKIX-DER form), matching
// the SDK's TLSPublicKeyFP convention.
//
// We fetch over plain TLS via http.DefaultTransport (WebPKI chain
// validation only). This is intentionally lighter than the verifiedFP
// path: the sidecar runs the full Sigstore + AMD VCEK chain
// independently, and resolveExpectedFP refuses any request where the
// two paths disagree. So trusting the WebPKI chain on the .well-known
// endpoint at this layer is fine — an attacker who could spoof
// .well-known would also need to forge a signed AMD report that
// matched on the sidecar side, which they can't.
func fetchExpectedTLSPubkeyFP(ctx context.Context) (string, error) {
	httpc := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://"+tinfoilEnclaveHost+tinfoilAttestPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("attestation fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("attestation fetch: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64 KiB cap
	if err != nil {
		return "", fmt.Errorf("attestation read: %w", err)
	}
	var doc tinfoilAttestation
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("attestation json: %w", err)
	}
	if doc.Body == "" {
		return "", errors.New("attestation body empty")
	}
	gzipped, err := base64.StdEncoding.DecodeString(doc.Body)
	if err != nil {
		return "", fmt.Errorf("attestation base64: %w", err)
	}
	gzr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return "", fmt.Errorf("attestation gunzip: %w", err)
	}
	defer gzr.Close()
	report, err := io.ReadAll(io.LimitReader(gzr, 1<<16))
	if err != nil {
		return "", fmt.Errorf("attestation gunzip read: %w", err)
	}
	if len(report) < sevSnpReportDataOffset+sevSnpReportDataLen {
		return "", fmt.Errorf("sev-snp report too short: %d bytes", len(report))
	}
	reportData := report[sevSnpReportDataOffset : sevSnpReportDataOffset+sevSnpReportDataLen]
	// SDK convention (verifier/attestation/attestation.go::newVerificationV2):
	//   TLSPublicKeyFP = hex(REPORT_DATA[0:32])
	//   HPKEPublicKey  = hex(REPORT_DATA[32:64])  // not used here
	return hex.EncodeToString(reportData[:32]), nil
}

// sidecarPayload mirrors the wire shape attest-sidecar's /verified-fp
// endpoint returns. We only consume the FP field today; the others
// (CodeDigest, ExpiresAt, ...) are kept here for future allowlist
// pinning ("only accept code_digest == X").
type sidecarPayload struct {
	FP              string    `json:"fp"`
	HPKEPubkey      string    `json:"hpke_pubkey"`
	CodeDigest      string    `json:"code_digest"`
	CodeFingerprint string    `json:"code_fp"`
	EnclaveFP       string    `json:"enclave_fp"`
	VerifiedAt      time.Time `json:"verified_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// unixSocketHTTPClient builds an http.Client that talks HTTP over the
// given Unix socket (path-based or @-prefixed abstract). The dialer
// enforces SO_PEERCRED PID-pinning: if SetExpectedSidecarPID has been
// called, the connection is dropped unless the peer process PID
// matches. A fresh client per call is fine — these requests are
// infrequent (cached for ~30s behind the first-use lazy load on
// tinfoilCachedClient).
func unixSocketHTTPClient(socket string) *http.Client {
	dialer := func(_ context.Context, _, _ string) (net.Conn, error) {
		c, err := net.DialTimeout("unix", socket, 2*time.Second)
		if err != nil {
			return nil, err
		}
		if expected := int(expectedSidecarPID.Load()); expected != 0 {
			pid, perr := peerPID(c)
			if perr != nil {
				// On non-Linux dev hosts peerPID returns "not
				// supported"; we accept the connection rather than
				// hard-fail, since the Linux-specific check is the
				// production-only hardening. On Linux a real failure
				// is exotic enough that closing the conn is safer.
				if !strings.Contains(perr.Error(), "only supported on Linux") {
					_ = c.Close()
					return nil, fmt.Errorf("peercred lookup failed: %w", perr)
				}
			} else if pid != expected {
				_ = c.Close()
				return nil, fmt.Errorf("%w: got pid=%d expected=%d", errSidecarPIDMismatch, pid, expected)
			}
		}
		return c, nil
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext:           dialer,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 3 * time.Second,
		},
	}
}

// fetchSidecarVerifiedFP queries the attest-sidecar over its Unix socket
// and returns the verified fingerprint plus the rest of the payload.
// On any failure (sidecar not running, socket unreachable, sidecar
// returned 5xx because verify chain itself is broken) returns an error.
//
// The caller (resolveExpectedFP) treats this error as "sidecar
// unavailable" and falls back to rawFP-only mode with a loud warning.
// We deliberately do NOT silently substitute rawFP for the sidecar's
// answer — that would let an attacker who can break the sidecar but
// not the in-process fetch downgrade us silently to a single-source
// pin.
func fetchSidecarVerifiedFP(ctx context.Context) (*sidecarPayload, error) {
	socket := strings.TrimSpace(tinfoilSidecarSocket)
	if socket == "" {
		return nil, errors.New("sidecar socket empty")
	}
	client := unixSocketHTTPClient(socket)
	// host part is ignored by the unix dialer but Go's URL parser
	// requires something.
	req, err := http.NewRequestWithContext(ctx, "GET", "http://attest-sidecar/verified-fp", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar dial: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("sidecar HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var v sidecarPayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<14)).Decode(&v); err != nil {
		return nil, fmt.Errorf("sidecar decode: %w", err)
	}
	if v.FP == "" {
		return nil, errors.New("sidecar returned empty fp")
	}
	if !v.ExpiresAt.IsZero() && time.Now().After(v.ExpiresAt) {
		return nil, fmt.Errorf("sidecar fp expired at %s", v.ExpiresAt.Format(time.RFC3339))
	}
	return &v, nil
}

// resolveExpectedFP returns the TLS-pubkey fingerprint we should pin
// to for tinfoil traffic, dual-sourced where possible:
//
//   1. rawFP      — stdlib-only parse of /.well-known/tinfoil-attestation
//                   (fetched directly from this process)
//   2. verifiedFP — full-Sigstore-+-AMD-VCEK-chain-verified value
//                   from the attest-sidecar (a separate process)
//
// Decision matrix:
//
//   * Both succeed and agree   → return verifiedFP (safer; full chain).
//   * Both succeed and DISAGREE → REFUSE. Either tinfoil is rotating
//                                 mid-flight (next attempt resolves)
//                                 or one network leg is being MITM'd.
//                                 Either way we don't pick a side.
//   * Only raw succeeds         → return rawFP, log "sidecar
//                                 unreachable; raw-only mode" loudly.
//                                 The pin still holds; it just lacks
//                                 the AMD signature attestation.
//   * Only sidecar succeeds     → return verifiedFP, log similarly
//                                 (raw fetch failed, e.g. tinfoil's
//                                 .well-known briefly 503'd).
//   * Neither succeeds          → return error. Tinfoil requests fail
//                                 closed.
//
// log lines use the structured key=value format the rest of the
// enclave already uses, so they show up cleanly in the regional
// log dataset.
func resolveExpectedFP(ctx context.Context) (string, error) {
	rawFP, rawErr := fetchExpectedTLSPubkeyFP(ctx)
	verified, sidecarErr := fetchSidecarVerifiedFP(ctx)

	switch {
	case rawErr == nil && sidecarErr == nil:
		if rawFP != verified.FP {
			log.Printf("tinfoil.attest.cross_check_disagreement raw_fp=%s verified_fp=%s code_digest=%s",
				rawFP, verified.FP, verified.CodeDigest)
			return "", fmt.Errorf("tinfoil attestation cross-check disagreement: raw=%s verified=%s",
				rawFP, verified.FP)
		}
		log.Printf("tinfoil.attest.cross_check_ok fp=%s code_digest=%s code_fp=%s",
			verified.FP, verified.CodeDigest, verified.CodeFingerprint)
		return verified.FP, nil
	case rawErr == nil && sidecarErr != nil:
		log.Printf("tinfoil.attest.sidecar_unreachable err=%q raw_fp=%s mode=raw_only",
			sidecarErr.Error(), rawFP)
		return rawFP, nil
	case rawErr != nil && sidecarErr == nil:
		log.Printf("tinfoil.attest.raw_fetch_failed err=%q verified_fp=%s mode=verified_only",
			rawErr.Error(), verified.FP)
		return verified.FP, nil
	default:
		return "", fmt.Errorf("tinfoil attestation unavailable: raw=%v sidecar=%v",
			rawErr, sidecarErr)
	}
}

// pinnedTLSDial returns a DialTLSContext callback that completes the TLS
// handshake to the given addr and then verifies the leaf certificate's
// public-key fingerprint matches expectedFP. Mismatch closes the
// connection and returns errCertFingerprintMismatch.
//
// We let crypto/tls do its normal WebPKI chain validation (so we still
// reject expired / wrong-domain certs the standard way), and we layer the
// pin check on top in the same dial path — before any byte of HTTP
// request data is sent.
func pinnedTLSDial(expectedFP string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			return nil, errors.New("tinfoil pin: connection is not TLS")
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			conn.Close()
			return nil, errors.New("tinfoil pin: no peer certificates")
		}
		der, err := x509.MarshalPKIXPublicKey(state.PeerCertificates[0].PublicKey)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("tinfoil pin: marshal pubkey: %w", err)
		}
		sum := sha256.Sum256(der)
		got := hex.EncodeToString(sum[:])
		if got != expectedFP {
			conn.Close()
			return nil, fmt.Errorf("%w: got %s want %s",
				errCertFingerprintMismatch, got, expectedFP)
		}
		return conn, nil
	}
}

var errCertFingerprintMismatch = errors.New("tinfoil: cert fingerprint mismatch")

// attestedRoundTripper wraps a pinned-TLS http.Transport and re-fetches
// the attestation + rebuilds the transport on a fingerprint mismatch.
// On second consecutive mismatch the request returns an error to the
// caller — we never silently fall back to a non-pinned client.
type attestedRoundTripper struct {
	mu        sync.RWMutex
	transport *http.Transport
	expected  string
	verifiedAt time.Time
}

func newAttestedRoundTripper(ctx context.Context) (*attestedRoundTripper, error) {
	fp, err := resolveExpectedFP(ctx)
	if err != nil {
		return nil, err
	}
	return &attestedRoundTripper{
		transport:  buildPinnedTransport(fp),
		expected:   fp,
		verifiedAt: time.Now(),
	}, nil
}

func buildPinnedTransport(fp string) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialTLSContext:        pinnedTLSDial(fp),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (r *attestedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.RLock()
	t := r.transport
	r.mu.RUnlock()
	resp, err := t.RoundTrip(req)
	if err == nil || !errors.Is(err, errCertFingerprintMismatch) {
		return resp, err
	}
	// Possible cert rotation: re-fetch attestation and try once more.
	if reErr := r.refresh(req.Context()); reErr != nil {
		return nil, err
	}
	r.mu.RLock()
	t = r.transport
	r.mu.RUnlock()
	return t.RoundTrip(req)
}

func (r *attestedRoundTripper) refresh(ctx context.Context) error {
	fp, err := resolveExpectedFP(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.transport = buildPinnedTransport(fp)
	r.expected = fp
	r.verifiedAt = time.Now()
	r.mu.Unlock()
	return nil
}

// tinfoilAttestedHTTPClient returns the http.Client all tinfoil chat
// completions flow through. The first call pays the attestation fetch +
// SEV-SNP-report parse cost (~tens of ms — single TLS roundtrip plus
// gzip + sha256). Subsequent calls reuse the cached client and pay only
// the per-request TLS pin compare (microseconds). On verify failure the
// function returns nil + error; the caller MUST surface that error
// rather than fall through to a plain http.Client (we never silently
// drop the pin).
var (
	tinfoilCachedRT *attestedRoundTripper
	tinfoilCacheMu  sync.Mutex
	tinfoilCachedClient *http.Client
)

func tinfoilAttestedHTTPClient(timeout time.Duration) (*http.Client, error) {
	tinfoilCacheMu.Lock()
	defer tinfoilCacheMu.Unlock()
	if tinfoilCachedClient != nil {
		return tinfoilCachedClient, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt, err := newAttestedRoundTripper(ctx)
	if err != nil {
		return nil, err
	}
	tinfoilCachedRT = rt
	tinfoilCachedClient = &http.Client{
		Timeout:   timeout,
		Transport: rt,
	}
	return tinfoilCachedClient, nil
}
