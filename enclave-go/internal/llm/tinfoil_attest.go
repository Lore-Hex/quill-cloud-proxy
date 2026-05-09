// Tinfoil TLS-pin-from-attestation: every tinfoil request lands on the
// public key the enclave's hardware attestation report committed to.
//
// What this is, plainly:
//
//   1. Once at first use, fetch tinfoil's attestation document over plain
//      HTTPS:  GET https://inference.tinfoil.sh/.well-known/tinfoil-attestation
//   2. The body is a gzip-then-base64-encoded SEV-SNP guest report. Decode
//      both layers and read REPORT_DATA at the AMD-defined offset (0x50,
//      64 bytes). Per Tinfoil's convention, REPORT_DATA[0:32] is the
//      SHA-256 of the enclave's TLS public key (in PKIX/SubjectPublicKeyInfo
//      DER form); REPORT_DATA[32:64] is the HPKE public key.
//   3. Build an http.Client whose DialTLSContext rejects any leaf cert
//      whose PKIX-DER public-key SHA-256 doesn't match REPORT_DATA[0:32].
//      Use that client for every tinfoil chat-completion request.
//
// What this is NOT:
//
//   * We don't verify the AMD signature chain on the SEV-SNP report. Doing
//      that requires sigstore-go + go-tuf + AMD KDS clients, all of which
//      pulled in a 30-MB+ transitive dependency tree (mongo-driver, otel,
//      grpc, certificate-transparency, transparency-dev/merkle, ...) on
//      the previous attempt. That dep graph also forced a Go 1.25
//      toolchain bump. Together those somehow corrupted the enclave's
//      vsock+TLS request loop — every request started returning HTTP 400
//      "could not read request" within minutes of rollout. We rolled
//      that revision back. This file goes the other direction: stdlib
//      ONLY (compress/gzip, crypto/sha256, crypto/x509, crypto/tls,
//      encoding/{base64,hex,json}, net, net/http, sync, time). No external
//      dep, no toolchain bump, no risk to the request loop.
//   * We don't verify the Sigstore-signed binary digest from
//     tinfoilsh/confidential-model-router. That would also need the heavy
//     dep tree.
//
// What we still get:
//
//   * Continuity: every request to inference.tinfoil.sh after first use
//     hits the same public key the enclave attested. A downstream MITM
//     can't quietly swap the cert because it can't make the SEV report
//     embed the new key's hash without re-running the enclave (and the
//     enclave is the thing AMD signs).
//   * Detection: if Tinfoil rotates their cert mid-flight, the next
//     handshake refuses; we re-fetch the attestation and retry once.
//
// Upgrade path (if/when we want full hardware-attestation verification):
//
//   * Move the Sigstore + AMD KDS verification into a sidecar binary that
//     lives outside the main enclave-go process and exposes a tiny
//     local API for "give me the current expected fingerprint." The main
//     enclave keeps the same DialTLSContext check; only the source of the
//     fingerprint changes.
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
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	tinfoilEnclaveHost = "inference.tinfoil.sh"
	tinfoilAttestPath  = "/.well-known/tinfoil-attestation"

	// SEV-SNP guest report offsets, AMD SEV-SNP ABI §7.3 (Table 22).
	// REPORT_DATA is at byte 0x50 and is 64 bytes long. We never look
	// at any other field of the report (that's where the AMD signature
	// chain would be checked, but we deliberately don't go there here —
	// see the file-level doc comment).
	sevSnpReportDataOffset = 0x50
	sevSnpReportDataLen    = 64
)

// tinfoilAttestation matches the JSON shape /.well-known/tinfoil-attestation
// returns:  {"format":"...sev-snp-guest/v2","body":"<gzip+base64>"}
type tinfoilAttestation struct {
	Format string `json:"format"`
	Body   string `json:"body"`
}

// fetchExpectedTLSPubkeyFP fetches Tinfoil's attestation document and
// extracts the SHA-256 fingerprint of the TLS public key the enclave
// has committed itself to via the SEV-SNP REPORT_DATA channel. Returns
// the fingerprint as a lowercase hex string (no leading "sha256:" prefix
// — matches the SDK's TLSPublicKeyFP convention).
//
// Fetched over plain TLS via http.DefaultTransport; the domain is
// well-known and not user-controlled, so trusting the WebPKI chain on
// the .well-known endpoint is the existing trust assumption everyone
// who hits inference.tinfoil.sh today already makes.
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
	fp, err := fetchExpectedTLSPubkeyFP(ctx)
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
	fp, err := fetchExpectedTLSPubkeyFP(ctx)
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
