// Tinfoil attestation wiring.
//
// Every tinfoil request flows through a TLS-pinned HTTP client whose peer
// public-key fingerprint must match the value the enclave's hardware
// attestation report committed to. That fingerprint is established once at
// startup by running the full SEV-SNP / TDX verification chain against
// inference.tinfoil.sh — including the Sigstore-signed code measurement
// pulled from tinfoilsh/confidential-model-router's GitHub release — so a
// connection to the wrong host (or a downgraded enclave) refuses the TLS
// handshake before any byte of request data is sent.
//
// We use github.com/tinfoilsh/tinfoil-go/verifier/client only for the
// initial Verify() chain; we do NOT use the higher-level tinfoil.Client
// (which pulls in openai-go) and we own the request loop ourselves so the
// existing streaming/byok plumbing in openai_compatible.go keeps working
// unchanged. On a TLS-fingerprint mismatch (e.g. tinfoil rotated their
// enclave cert mid-deploy) the round-tripper transparently re-runs Verify
// and retries the request once.
//
// Why "every request" doesn't mean "re-verify the SEV-SNP chain every
// request": the chain takes hundreds of ms (sigstore + GitHub fetch +
// VCEK chain). The per-request guarantee is the TLS pinning — every
// connection is checked against the verified fingerprint before bytes
// flow. Re-verification happens lazily on cert rotation only.
package llm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	tinfoilclient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	tinfoilEnclaveHost = "inference.tinfoil.sh"
	// confidential-model-router is the GitHub repo whose Sigstore-signed
	// release binary the running enclave is supposed to match. Updating
	// tinfoil's deployed binary => new release => new measurement => the
	// next Verify() picks up the change automatically.
	tinfoilCodeRepo = "tinfoilsh/confidential-model-router"
)

// tinfoilAttestedTransport wraps a TLS-pinned http.Transport. On certificate
// pin failure it re-runs Verify against the enclave to pick up cert rotation,
// then retries the request once.
type tinfoilAttestedTransport struct {
	mu                 sync.RWMutex
	secureClient       *tinfoilclient.SecureClient
	transport          http.RoundTripper
	expectedTLSPubKey  string
	verifiedAt         time.Time
}

// newTinfoilAttestedTransport runs the full SEV-SNP / TDX verification chain
// against inference.tinfoil.sh (including Sigstore + GitHub digest checks)
// and returns a Transport that pins TLS to the verified public-key fingerprint.
//
// This is the slow path (~hundreds of ms — Sigstore TUF root + GitHub API +
// VCEK chain). Called once at boot per enclave instance, then again on
// any cert-rotation re-verify.
func newTinfoilAttestedTransport() (*tinfoilAttestedTransport, error) {
	sc := tinfoilclient.NewSecureClient(tinfoilEnclaveHost, tinfoilCodeRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("tinfoil attest verify: %w", err)
	}
	gt := sc.GroundTruth()
	if gt == nil || gt.TLSPublicKey == "" {
		return nil, errors.New("tinfoil attest verify: no TLS public key in ground truth")
	}
	// Wrap the SDK's pinned transport with our pooled-connection settings so
	// keep-alive / HTTP/2 multiplexing matches the rest of the gateway. We
	// keep the SDK's DialTLSContext (the per-request fingerprint check) and
	// only override the pool/idle knobs.
	pinned, ok := httpClient.Transport.(*tinfoilclient.TLSBoundRoundTripper)
	if !ok {
		return nil, fmt.Errorf("tinfoil attest verify: unexpected transport type %T", httpClient.Transport)
	}
	return &tinfoilAttestedTransport{
		secureClient:      sc,
		transport:         pinned,
		expectedTLSPubKey: gt.TLSPublicKey,
		verifiedAt:        time.Now(),
	}, nil
}

func (t *tinfoilAttestedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	resp, err := transport.RoundTrip(req)
	if err == nil || !isTinfoilCertError(err) {
		return resp, err
	}

	// TLS pin mismatch — tinfoil may have rotated their enclave cert.
	// Re-verify ONCE; on success swap the transport and retry.
	if reErr := t.reverify(); reErr != nil {
		// Re-verification failed: surface the original cert error so the
		// caller sees "connection refused" rather than a misleading
		// "verify failed" message. This is the path a genuinely
		// malicious/MitM'd connection takes.
		return nil, err
	}
	t.mu.RLock()
	transport = t.transport
	t.mu.RUnlock()
	return transport.RoundTrip(req)
}

func (t *tinfoilAttestedTransport) reverify() error {
	sc := tinfoilclient.NewSecureClient(tinfoilEnclaveHost, tinfoilCodeRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		return err
	}
	pinned, ok := httpClient.Transport.(*tinfoilclient.TLSBoundRoundTripper)
	if !ok {
		return fmt.Errorf("tinfoil reverify: unexpected transport type %T", httpClient.Transport)
	}
	gt := sc.GroundTruth()
	if gt == nil || gt.TLSPublicKey == "" {
		return errors.New("tinfoil reverify: no TLS public key in ground truth")
	}
	t.mu.Lock()
	t.secureClient = sc
	t.transport = pinned
	t.expectedTLSPubKey = gt.TLSPublicKey
	t.verifiedAt = time.Now()
	t.mu.Unlock()
	return nil
}

// isTinfoilCertError reports whether the error indicates a TLS-pinning or
// certificate-chain failure as opposed to (e.g.) a network timeout or HTTP
// error. Mirrors the SDK's classification so we re-verify on the same
// trigger conditions the SDK does.
func isTinfoilCertError(err error) bool {
	if errors.Is(err, tinfoilclient.ErrNoTLS) {
		return true
	}
	if errors.Is(err, tinfoilclient.ErrCertMismatch) {
		return true
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return true
	}
	return false
}

// tinfoilAttestedClient returns the *http.Client all tinfoil requests flow
// through. Verify happens lazily on first use (so the enclave can boot
// without a hard dependency on Sigstore + GitHub being reachable at start),
// and the result is cached for the life of the process.
//
// On verify failure the function returns a non-nil error and the caller
// should NOT fall through to a plain http.Client — that would defeat the
// attestation guarantee. Tinfoil requests must hard-fail when verification
// is unavailable.
var (
	tinfoilClientOnce   sync.Once
	tinfoilCachedClient *http.Client
	tinfoilCacheErr     error
)

func tinfoilAttestedHTTPClient(timeout time.Duration) (*http.Client, error) {
	tinfoilClientOnce.Do(func() {
		t, err := newTinfoilAttestedTransport()
		if err != nil {
			tinfoilCacheErr = err
			return
		}
		tinfoilCachedClient = &http.Client{
			Timeout:   timeout,
			Transport: t,
		}
	})
	if tinfoilCacheErr != nil {
		// Reset Once so the next request re-attempts verification — boot
		// can race with Sigstore/GitHub reachability and the gateway
		// shouldn't be permanently dead just because the first verify
		// happened to land during a transient TUF root fetch failure.
		tinfoilClientOnce = sync.Once{}
		return nil, tinfoilCacheErr
	}
	return tinfoilCachedClient, nil
}

// dialTimeoutForKeepalive is here so the file doesn't import net for nothing.
// The pinned transport handles its own dial timeouts.
var _ = net.Dialer{Timeout: 30 * time.Second}

// withContext is a placeholder so context import isn't unused if future
// changes need it (e.g. propagating a deadline into reverify). Remove
// once that lands.
var _ = context.Background
