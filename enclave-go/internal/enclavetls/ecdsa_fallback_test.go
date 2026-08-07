package enclavetls

import (
	"crypto/tls"
	"errors"
	"testing"
)

// A ClientHello from a modern OpenSSL 3.5+ client: post-quantum and X25519
// groups, NO P-256 — but signature_algorithms that plainly include ECDSA.
//
// autocert's supportsECDSA() reads only the groups, concludes "needs RSA", and
// looks up "<host>+rsa". Where no RSA cert was ever issued that is TLS alert 80
// and a hard connection failure, for a client that would have been perfectly
// happy with the ECDSA leaf the server is already serving everyone else.
//
// Reproduced live 2026-08-07 against both Azure enclave regions:
//
//	openssl s_client -groups X25519  -> failed
//	openssl s_client -groups P-256   -> succeeded
//
// curl was unaffected, which is why no monitor caught it.
func modernHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:      "api-azure-sea.trustedrouter.com",
		SupportedCurves: []tls.CurveID{tls.X25519},
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
		},
		SupportedVersions: []uint16{tls.VersionTLS13},
	}
}

func TestP256IsAddedWhenAbsent(t *testing.T) {
	hello := modernHello()
	got := withP256(hello)

	found := false
	for _, c := range got.SupportedCurves {
		if c == tls.CurveP256 {
			found = true
		}
	}
	if !found {
		t.Fatalf("P-256 not added: %v", got.SupportedCurves)
	}
	// The original curves must survive — dropping X25519 would change the key
	// exchange the client actually negotiated.
	if got.SupportedCurves[0] != tls.X25519 {
		t.Errorf("original curves not preserved: %v", got.SupportedCurves)
	}
}

func TestTheCallersHelloIsNotMutated(t *testing.T) {
	// hello belongs to crypto/tls and is REUSED across lookups on the same
	// connection. Appending in place would corrupt live handshake state, and
	// the corruption would be intermittent and load-dependent — the worst
	// possible shape to debug.
	hello := modernHello()
	before := append([]tls.CurveID(nil), hello.SupportedCurves...)

	_ = withP256(hello)

	if len(hello.SupportedCurves) != len(before) {
		t.Fatalf("caller's hello was mutated: %v -> %v", before, hello.SupportedCurves)
	}
	for i := range before {
		if hello.SupportedCurves[i] != before[i] {
			t.Fatalf("caller's hello was mutated: %v -> %v", before, hello.SupportedCurves)
		}
	}
}

func TestAHelloThatAlreadyOffersP256IsReturnedUnchanged(t *testing.T) {
	// Then the failure was something else — a genuinely missing certificate, a
	// HostPolicy rejection — and retrying with an identical hello would just
	// double the work and log noise while changing nothing.
	hello := modernHello()
	hello.SupportedCurves = []tls.CurveID{tls.CurveP256, tls.X25519}

	if got := withP256(hello); got != hello {
		t.Fatal("hello already advertising P-256 should be returned as-is")
	}
}

func TestNilCurvesStillGetsP256(t *testing.T) {
	// nil SupportedCurves means "client said nothing", which autocert treats as
	// ECDSA-capable — but being explicit costs nothing and keeps the retry
	// meaningful if that ever changes.
	hello := modernHello()
	hello.SupportedCurves = nil

	got := withP256(hello)
	if len(got.SupportedCurves) != 1 || got.SupportedCurves[0] != tls.CurveP256 {
		t.Fatalf("got %v", got.SupportedCurves)
	}
	if hello.SupportedCurves != nil {
		t.Fatal("caller's hello was mutated")
	}
}

// --------------------------------------------------------------------------
// THE WIRING, not just the helper.
// --------------------------------------------------------------------------
// withP256 can be perfect and the bug still ships if the GetCertificate path
// never calls it. That is exactly how the original defect existed — every
// individual piece was fine. These drive the same function the live
// tls.Config calls, with a fake standing in for autocert.

var errNoRSACert = errors.New("acme/autocert: missing certificate")

// A getter that behaves like autocert against a cache holding ONLY an ECDSA
// cert: it serves clients advertising P-256 and refuses everyone else.
func ecdsaOnlyGetter(calls *[]*tls.ClientHelloInfo) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		*calls = append(*calls, hello)
		for _, c := range hello.SupportedCurves {
			if c == tls.CurveP256 {
				return &tls.Certificate{Certificate: [][]byte{{0x01}}}, nil
			}
		}
		return nil, errNoRSACert
	}
}

func hasP256(hello *tls.ClientHelloInfo) bool {
	for _, c := range hello.SupportedCurves {
		if c == tls.CurveP256 {
			return true
		}
	}
	return false
}

func TestModernClientWithoutP256IsServed(t *testing.T) {
	var calls []*tls.ClientHelloInfo
	cert, err := getCertificateWithECDSAFallback(ecdsaOnlyGetter(&calls), modernHello())

	if err != nil {
		t.Fatalf("a client that omits P-256 was refused a certificate: %v", err)
	}
	if cert == nil {
		t.Fatal("no certificate returned")
	}
	// THE ORDERING IS THE FIX. The ECDSA lookup must be the FIRST call, not a
	// retry after failure: a cache miss on "<host>+rsa" sends autocert into an
	// ACME order that blocks on the network, and against a rate-limited CA the
	// client gives up mid-handshake with no ServerHello at all. Asserting only
	// "a cert came back" would pass against that hang.
	if len(calls) != 1 {
		t.Fatalf("expected exactly one lookup, got %d — the blocking RSA path was hit", len(calls))
	}
	if !hasP256(calls[0]) {
		t.Fatal("the first lookup did not ask for the ECDSA certificate")
	}
}

func TestAClientAdvertisingP256IsUnaffected(t *testing.T) {
	var calls []*tls.ClientHelloInfo
	hello := modernHello()
	hello.SupportedCurves = []tls.CurveID{tls.CurveP256}

	if _, err := getCertificateWithECDSAFallback(ecdsaOnlyGetter(&calls), hello); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected a single lookup, got %d", len(calls))
	}
}

func TestAClientThatCannotUseECDSAIsNotDiverted(t *testing.T) {
	// A genuine RSA-only client must still reach autocert's RSA path, even
	// though that may open an ACME order. Serving it an ECDSA leaf would be a
	// handshake failure of our own making.
	var calls []*tls.ClientHelloInfo
	hello := modernHello()
	hello.SignatureSchemes = []tls.SignatureScheme{tls.PSSWithSHA256, tls.PKCS1WithSHA256}

	_, _ = getCertificateWithECDSAFallback(ecdsaOnlyGetter(&calls), hello)

	if len(calls) != 1 {
		t.Fatalf("expected a single lookup, got %d", len(calls))
	}
	if hasP256(calls[0]) {
		t.Fatal("an RSA-only client was diverted to the ECDSA certificate")
	}
}

func TestAnUnrelatedFailureKeepsItsOriginalError(t *testing.T) {
	// The ECDSA attempt must never rewrite the diagnosis. A HostPolicy
	// rejection has to surface as itself, or the next operator reads the wrong
	// error and debugs certificates instead of configuration.
	sentinel := errors.New("acme/autocert: host not configured in HostWhitelist")
	ecdsaNoise := errors.New("acme/autocert: missing certificate")
	var calls int
	_, err := getCertificateWithECDSAFallback(
		func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			calls++
			if hasP256(hello) {
				return nil, ecdsaNoise
			}
			return nil, sentinel
		},
		modernHello(),
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("the unmodified hello's error was replaced by %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the ECDSA attempt then the original, got %d calls", calls)
	}
}
