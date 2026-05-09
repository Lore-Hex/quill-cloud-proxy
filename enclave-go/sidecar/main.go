// attest-sidecar: SEV-SNP-verified TLS public-key fingerprint provider.
//
// Why this binary exists at all
// =============================
//
// Tinfoil's full attestation chain is verified by importing
// github.com/tinfoilsh/tinfoil-go/verifier/client. That package's
// transitive deps (sigstore-go, go-tuf/v2, certificate-transparency-go,
// transparency-dev/merkle, mongo-driver, otel, grpc, protobuf,
// sigstore/rekor, ...) are large enough that linking them into the
// MAIN enclave-go binary corrupted its vsock+TLS request loop —
// every request started returning HTTP 400 "could not read request"
// within minutes of rollout (deploy 25592563258), tripping the canary
// at 2-min consecutive-down. We rolled that revision back.
//
// This sidecar isolates that heavy verification chain into its own Go
// module with its own go.mod, so none of those packages get linked
// into the main enclave's symbol table. The main enclave keeps its
// proven-stable dep graph and just talks to this sidecar over a
// Unix socket. If sigstore/whatever ever breaks the world, only this
// binary blows up; the main enclave keeps serving requests under
// the stdlib-only fingerprint pin (with a loud "sidecar unreachable"
// log).
//
// What this binary does
// =====================
//
//   1. On startup and every reverifyInterval (10m by default), runs
//      tinfoil-go's full Verify() chain:
//        * Fetches the latest GitHub release digest of
//          tinfoilsh/confidential-model-router.
//        * Pulls the Sigstore-signed code-measurement bundle from
//          the GitHub release attestation.
//        * Verifies the bundle against the embedded Sigstore trusted
//          root.
//        * Fetches the live SEV-SNP guest report from
//          inference.tinfoil.sh/.well-known/tinfoil-attestation.
//        * Recreates the AMD VCEK chain, verifies the SEV-SNP
//          signature against AMD's root, and confirms the report's
//          measurement matches the Sigstore-attested code measurement.
//        * Extracts the TLS public-key fingerprint from the verified
//          report's REPORT_DATA.
//
//   2. Caches the verified fingerprint and serves it over a Unix
//      socket (default /run/tinfoil-attest.sock; can also use Linux
//      abstract sockets via @-prefix paths if /run is read-only).
//
//   3. Exponential-backoff retry on Verify failures. Old verified
//      values are NOT served past their ExpiresAt — better to hard-fail
//      a request than to serve a stale-and-rotated FP.
//
// How the main enclave uses it
// ============================
//
// internal/llm/tinfoil_attest.go (in the main enclave) does TWO
// independent fetches of the attestation document:
//
//   * rawFP      — its own stdlib-only parse of /.well-known/...
//   * verifiedFP — this sidecar's full-chain-verified value
//
// and refuses any tinfoil request where rawFP != verifiedFP. The
// cross-check defends against an attacker who owns one network leg
// (one fetch sees a forged report) but not both, and against a
// compromised sidecar that lies about its verification result.
//
// Trust properties summary
// ========================
//
//   * MITM on either path alone → caught (the other path disagrees).
//   * Compromised sidecar that returns wrong FP → caught (rawFP from
//     in-process disagrees).
//   * Compromised sidecar that fails-open by returning the rawFP →
//     this binary doesn't see rawFP, so it can't pretend to have
//     verified what it didn't. Best the attacker can do is downgrade
//     to "sidecar unavailable" (which the main enclave logs loudly).
//   * Compromised process running this sidecar's code in-place →
//     same threat model as the main enclave being compromised; the
//     cross-check doesn't help, but Confidential Space's hardware
//     attestation does (a different layer).
//
// What this design assumes does NOT happen
// ========================================
//
// The cross-check is single-leg defense-in-depth. It does NOT defend
// against an attacker who simultaneously breaches MULTIPLE independent
// organizations' infrastructure on a coordinated timeline:
//
//   (a) ships a malicious version of THIS binary in our published
//       enclave image (= compromise our build pipeline / Artifact
//       Registry), AND
//   (b) modifies the data GitHub serves for tinfoilsh/confidential-
//       model-router release Sigstore bundles, so a Verify chain run
//       against the forged data still produces a valid signature, AND
//   (c) makes either inference.tinfoil.sh's .well-known endpoint or
//       our network leg to it serve a matching forged SEV-SNP report
//
// That requires coordinated breaches of us, GitHub, and tinfoil/AMD
// at once — out of scope for this design. AMD's signing key is the
// hard floor: forging a SEV-SNP report requires it, and CPU-resident
// keys are not extractable.
//
// Note that the "malicious sidecar binary" leg above is specifically
// a SUPPLY-CHAIN attack on our build, not a runtime disk-write. The
// running /attest-sidecar binary is part of our Confidential Space
// container image, so its bytes are sealed into the same SEV-SNP
// measurement that anyone calling our enclave's /attestation
// endpoint already verifies. A runtime swap inside the enclave VM
// is blocked by the TEE; a supply-chain swap shows up as a measured-
// boot mismatch that downstream attestation verifiers (including
// tinfoil's own clients of US, if they do dual-source on us) catch.
// See enclave-go/internal/llm/tinfoil_attest.go for the full
// threat-model write-up on the consumer side.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	tinfoilclient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	defaultEnclaveHost = "inference.tinfoil.sh"
	defaultCodeRepo    = "tinfoilsh/confidential-model-router"

	// Default Unix-socket path. Override via -socket. Use "@<name>" for
	// a Linux abstract socket (no filesystem entry — useful when the
	// runtime image is FROM scratch and /run isn't writable).
	defaultSocketPath = "@tinfoil-attest"

	// How often to re-run the full verification chain. Tinfoil's
	// release cadence is on the order of days; 10 min picks up cert
	// rotation + new binary releases within bounded time without
	// burning Sigstore/GitHub roundtrips.
	defaultReverifyInterval = 10 * time.Minute

	// On verify failure, retry with exponential backoff. Bounded so
	// we don't drift into hour-long gaps while the network is sad.
	initialBackoff = 2 * time.Second
	maxBackoff     = 1 * time.Minute

	// How long after a successful verification we keep serving the
	// value. Bigger than reverifyInterval so a single failed reverify
	// doesn't tip us into "expired"; small enough that an attacker
	// can't hold us at a stale FP forever (e.g. by black-holing
	// reverifies after compromising the sidecar's network leg).
	gracePeriod = 5 * time.Minute
)

type verifiedPayload struct {
	FP              string    `json:"fp"`               // hex sha256 of TLS pubkey DER
	HPKEPubkey      string    `json:"hpke_pubkey"`      // hex, REPORT_DATA[32:64]
	CodeDigest      string    `json:"code_digest"`      // GitHub release digest
	CodeFingerprint string    `json:"code_fp"`          // tinfoil CodeFingerprint
	EnclaveFP       string    `json:"enclave_fp"`       // tinfoil EnclaveFingerprint
	VerifiedAt      time.Time `json:"verified_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type state struct {
	mu      sync.RWMutex
	current *verifiedPayload
	lastErr error
}

func (s *state) set(v *verifiedPayload, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v != nil {
		s.current = v
	}
	s.lastErr = err
}

// snapshot returns the current verified value if it's still inside the
// grace window, or an error if not. Callers must NOT use a value past
// ExpiresAt — the cross-check on the main enclave side relies on
// "verified within the last reverifyInterval+grace" being true.
func (s *state) snapshot() (*verifiedPayload, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		if s.lastErr != nil {
			return nil, s.lastErr
		}
		return nil, errors.New("no successful verification yet")
	}
	if time.Now().After(s.current.ExpiresAt) {
		return nil, fmt.Errorf("attestation expired at %s (last err: %v)", s.current.ExpiresAt.Format(time.RFC3339), s.lastErr)
	}
	out := *s.current
	return &out, nil
}

// runVerify runs tinfoil-go's full Verify chain and translates the
// resulting GroundTruth into our wire shape.
func runVerify(enclaveHost, codeRepo string, reverifyInterval time.Duration) (*verifiedPayload, error) {
	sc := tinfoilclient.NewSecureClient(enclaveHost, codeRepo)
	gt, err := sc.Verify()
	if err != nil {
		return nil, fmt.Errorf("tinfoil verify: %w", err)
	}
	if gt == nil || gt.TLSPublicKey == "" {
		return nil, errors.New("verify returned no ground truth")
	}
	now := time.Now()
	return &verifiedPayload{
		FP:              gt.TLSPublicKey,
		HPKEPubkey:      gt.HPKEPublicKey,
		CodeDigest:      gt.Digest,
		CodeFingerprint: gt.CodeFingerprint,
		EnclaveFP:       gt.EnclaveFingerprint,
		VerifiedAt:      now,
		ExpiresAt:       now.Add(reverifyInterval + gracePeriod),
	}, nil
}

// reverifyLoop runs verify on a timer with exponential backoff on failure.
func reverifyLoop(ctx context.Context, s *state, enclaveHost, codeRepo string, reverifyInterval time.Duration) {
	backoff := initialBackoff
	for {
		v, err := runVerify(enclaveHost, codeRepo, reverifyInterval)
		s.set(v, err)
		if err != nil {
			log.Printf("verify failed: %v (next attempt in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = initialBackoff
		log.Printf("verify ok: tls_fp=%s… code_digest=%s… expires=%s",
			truncate(v.FP, 16), truncate(v.CodeDigest, 12),
			v.ExpiresAt.Format(time.RFC3339))
		select {
		case <-ctx.Done():
			return
		case <-time.After(reverifyInterval):
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	var (
		flagEnclaveHost   = flag.String("host", defaultEnclaveHost, "tinfoil enclave hostname")
		flagCodeRepo      = flag.String("repo", defaultCodeRepo, "tinfoil GitHub code repo")
		flagSocketPath    = flag.String("socket", defaultSocketPath, "Unix socket path; @-prefix means abstract socket")
		flagReverifyEvery = flag.Duration("reverify", defaultReverifyInterval, "how often to re-run full verify")
	)
	flag.Parse()

	log.SetPrefix("attest-sidecar: ")
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)
	log.Printf("starting; enclave=%s repo=%s socket=%s reverify=%s",
		*flagEnclaveHost, *flagCodeRepo, *flagSocketPath, *flagReverifyEvery)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	s := &state{}
	go reverifyLoop(ctx, s, *flagEnclaveHost, *flagCodeRepo, *flagReverifyEvery)

	// If using a path-based socket, remove any stale entry from a
	// crashed previous run. Abstract sockets (@-prefix) don't need
	// this — they go away with the process automatically.
	socket := *flagSocketPath
	if !strings.HasPrefix(socket, "@") {
		_ = os.Remove(socket)
	}
	rawListener, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalf("listen unix %s: %v", socket, err)
	}
	defer rawListener.Close()
	if !strings.HasPrefix(socket, "@") {
		// 0600: only the same UID (the main enclave runs as the same
		// uid as this sidecar in the Confidential Space VM) can read.
		if err := os.Chmod(socket, 0o600); err != nil {
			log.Printf("warn: chmod %s: %v", socket, err)
		}
	}
	// Wrap with a SO_PEERCRED-checking accept loop. Any peer whose UID
	// doesn't match our own gets dropped before http.Server even sees
	// the connection. With path-based sockets this is belt-and-
	// suspenders (the 0600 already enforces UID); with abstract
	// sockets (the default) it's the only filesystem-independent UID
	// enforcement we get, since abstract sockets bypass the
	// permission-bit check.
	listener := &uidEnforcingListener{
		Listener: rawListener,
		expected: os.Getuid(),
	}
	log.Printf("serving on unix:%s (uid_check=%d)", socket, listener.expected)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/verified-fp", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.snapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		log.Println("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
	log.Println("exited")
}

// uidEnforcingListener wraps a Unix socket listener and rejects any
// accepted connection whose peer process UID (read via SO_PEERCRED)
// doesn't match `expected`. Connections that fail the check are
// closed immediately, before any HTTP byte is read.
//
// Why: the abstract-socket bind path (`@tinfoil-attest`) doesn't have
// filesystem permission bits, so anyone in the same network namespace
// could connect. Inside Confidential Space the trust boundary is the
// whole VM and this is paranoia. Outside Confidential Space (e.g.
// shared-host development scenarios) it cuts off a real attack
// surface for free.
//
// On non-Linux builds (peerUID always errors), accepted connections
// are passed through unchanged — see peercred_other.go.
type uidEnforcingListener struct {
	net.Listener
	expected int
}

func (l *uidEnforcingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err != nil {
			// On non-Linux dev hosts we let everything through.
			// On Linux a real getsockopt error is exotic enough that
			// erring loudly + dropping the conn is the safer move.
			if isUnsupportedPeercred(err) {
				return c, nil
			}
			log.Printf("rejected connection: peercred lookup failed: %v", err)
			_ = c.Close()
			continue
		}
		if uid != l.expected {
			log.Printf("rejected connection: peer uid=%d expected=%d", uid, l.expected)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

func isUnsupportedPeercred(err error) bool {
	return err != nil && strings.Contains(err.Error(), "only supported on Linux")
}
