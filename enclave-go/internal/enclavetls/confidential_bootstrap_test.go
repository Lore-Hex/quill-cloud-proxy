package enclavetls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func TestTLS13OnlyUsesPreissuedECDSALeaf(t *testing.T) {
	const host = "primary.gateway.test"
	issued, err := NewSelfSigned(host)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encodeAutocertEntry(issued.Certificate.PrivateKey.(*ecdsa.PrivateKey), issued.Certificate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	cache := autocert.DirCache(t.TempDir())
	if err := cache.Put(context.Background(), host, blob); err != nil {
		t.Fatal(err)
	}
	pin, err := CachedDNS01PublicPin(context.Background(), cache, host)
	leaf, parseErr := x509.ParseCertificate(issued.Certificate.Certificate[0])
	if parseErr != nil || err != nil || pin != fmt.Sprintf("%x", sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) {
		t.Fatal("cached public fingerprint did not match the issued certificate")
	}
	srv, err := NewACMEWithCache(host, "", "http://127.0.0.1:1", cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello := &tls.ClientHelloInfo{
		ServerName: host, SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedCurves: []tls.CurveID{tls.CurveP256}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
	}
	cert, err := srv.tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Certificate[0], issued.Certificate.Certificate[0]) || len(hello.CipherSuites) != 1 {
		t.Fatal("wrong cached leaf or modified client cipher suites")
	}
}

func TestPreissueDoesNotReorderOrOverwriteCorruptEntries(t *testing.T) {
	ctx := context.Background()
	const host = "issuer.gateway.test"
	cache := autocert.DirCache(t.TempDir())
	cfg := DNS01Config{DNSName: host, Cache: cache, Provider: &recordingProvider{}, DirectoryURL: "https://production.example/directory"}
	var calls int
	withStubOrder(t, func(context.Context, DNS01Config, DNS01CA) error {
		calls++
		key, err := NewSelfSigned(host)
		if err != nil {
			return err
		}
		blob, err := encodeAutocertEntry(key.Certificate.PrivateKey.(*ecdsa.PrivateKey), key.Certificate.Certificate)
		if err != nil {
			return err
		}
		return cache.Put(ctx, host, blob)
	})
	for i := 0; i < 2; i++ {
		if err := PreissueDNS01(ctx, cfg, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := PreissueDNS01(ctx, cfg, true); err == nil {
		t.Fatal("forced production renewal")
	}
	if err := cache.Put(ctx, host, []byte("bad entry")); err != nil {
		t.Fatal(err)
	}
	if err := PreissueDNS01(ctx, cfg, false); err == nil || calls != 1 {
		t.Fatalf("bad cached entry overwritten: %v, %d orders", err, calls)
	}
}

func TestRenewalReusesAuthorizationAndPollsOriginalOrder(t *testing.T) {
	var polls atomic.Int32
	server := fakeACMEWith(t, func(w http.ResponseWriter, r *http.Request, base string) bool {
		switch r.URL.Path {
		case "/authz/1":
			fmt.Fprint(w, `{"status":"valid","identifier":{"type":"dns","value":"api-aws.trustedrouter.com"}}`)
		case "/order/1":
			if polls.Add(1) == 1 {
				fmt.Fprint(w, `{"status":"ready"}`)
			} else {
				fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, base+"/cert")
			}
		case "/finalize/1":
			// A processing response need not repeat the original Location header.
			fmt.Fprint(w, `{"status":"processing"}`)
		case "/cert":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"fixture certificate endpoint reached"}`)
		default:
			return false
		}
		return true
	})
	p := &recordingProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runDNS01Order(ctx, DNS01Config{DNSName: "api-aws.trustedrouter.com", Email: "ops@example.test", Cache: autocert.DirCache(t.TempDir()), HTTPClient: server.Client(), Provider: p}, DNS01CA{DirectoryURL: server.URL + "/directory"})
	if err == nil || !strings.Contains(err.Error(), "fixture certificate endpoint reached") || polls.Load() != 2 || len(p.added) != 0 {
		t.Fatalf("renewal did not reach certificate download without DNS mutation: %v, polls=%d, writes=%d", err, polls.Load(), len(p.added))
	}
}

func TestDNS01RateLimitedPrimaryReachesFallback(t *testing.T) {
	var orders atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "bm9uY2U")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/directory":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, server.URL+"/nonce", server.URL+"/account", server.URL+"/order")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			w.Header().Set("Location", server.URL+"/account/1")
			fmt.Fprint(w, `{"status":"valid"}`)
		case "/order":
			orders.Add(1)
			w.Header().Set("Retry-After", "86400")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"paused"}`)
		default:
			t.Errorf("unexpected ACME request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	original := orderCA
	fallbackReached := false
	withStubOrder(t, func(ctx context.Context, cfg DNS01Config, ca DNS01CA) error {
		if ca.DirectoryURL == server.URL+"/directory" {
			return original(ctx, cfg, ca)
		}
		fallbackReached = ctx.Err() == nil
		return ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := runDNS01Orders(ctx, DNS01Config{
		DNSName: "api.confidential.trustedrouter.com", Email: "acme@example.com",
		DirectoryURL: server.URL + "/directory", Cache: autocert.DirCache(t.TempDir()),
		HTTPClient: server.Client(), FallbackCAs: []DNS01CA{{DirectoryURL: "https://fallback.example/directory"}},
	})
	if err != nil || !fallbackReached || orders.Load() != 1 {
		t.Fatalf("primary 429 must reach fallback before deadline: err=%v fallback=%v orders=%d", err, fallbackReached, orders.Load())
	}
}

func TestConfidentialTLSDoesNotOrderCertificateOnCacheMiss(t *testing.T) {
	for _, host := range []string{"api.confidential.trustedrouter.com", "api.nytokenexchange.com", "api.confidential.nytokenexchange.com"} {
		t.Run(host, func(t *testing.T) { testDNS01TLSDoesNotOrderOnCacheMiss(t, host) })
	}
}

func testDNS01TLSDoesNotOrderOnCacheMiss(t *testing.T, host string) {
	var requests atomic.Int32
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ca.Close()
	cache := autocert.DirCache(t.TempDir())
	srv, err := NewACMEWithCache(host, "", ca.URL, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello := &tls.ClientHelloInfo{ServerName: host, SupportedCurves: []tls.CurveID{tls.CurveP256}}
	if _, err := srv.tlsConfig.GetCertificate(hello); err == nil {
		t.Fatal("missing certificate must fail closed")
	}
	if requests.Load() != 0 {
		t.Fatal("confidential readiness probe triggered a TLS-ALPN order before DNS publication")
	}
	// A DNS-01 certificate arriving later must become usable without a restart.
	issued, err := NewSelfSigned(host)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encodeAutocertEntry(issued.Certificate.PrivateKey.(*ecdsa.PrivateKey), issued.Certificate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Put(context.Background(), host, blob); err != nil {
		t.Fatal(err)
	}
	cert, err := srv.tlsConfig.GetCertificate(hello)
	if err != nil || cert == nil || requests.Load() != 0 {
		t.Fatalf("DNS-01 certificate unavailable: cert=%v err=%v requests=%d", cert != nil, err, requests.Load())
	}
	if _, err := srv.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.confidential.allyrouter.com"}); err == nil {
		t.Fatal("unconfigured confidential host must still be rejected")
	}
}

func TestConfidentialTLSRejectsWrongHostCacheEntry(t *testing.T) {
	const host = "api.confidential.trustedrouter.com"
	issued, _ := NewSelfSigned("api.trustedrouter.com")
	blob, _ := encodeAutocertEntry(issued.Certificate.PrivateKey.(*ecdsa.PrivateKey), issued.Certificate.Certificate)
	cache := autocert.DirCache(t.TempDir())
	if err := cache.Put(context.Background(), host, blob); err != nil {
		t.Fatal(err)
	}
	srv, err := NewACMEWithCache(host, "", "http://127.0.0.1:1", cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("wrong-host certificate must be rejected: %v", err)
	}
}

func TestConfidentialTLSRejectsExpiredAndNotYetValidCertificates(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(fmt.Sprintf("future=%v", future), func(t *testing.T) {
			const host = "api.confidential.trustedrouter.com"
			issued, err := NewSelfSigned(host)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(issued.Certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			leaf.NotBefore, leaf.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			if future {
				leaf.NotBefore, leaf.NotAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
			}
			key := issued.Certificate.PrivateKey.(*ecdsa.PrivateKey)
			der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			blob, err := encodeAutocertEntry(key, [][]byte{der})
			if err != nil {
				t.Fatal(err)
			}
			cache := autocert.DirCache(t.TempDir())
			if err := cache.Put(context.Background(), host, blob); err != nil {
				t.Fatal(err)
			}
			srv, err := NewACMEWithCache(host, "", "http://127.0.0.1:1", cache, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := srv.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err == nil || !strings.Contains(err.Error(), "validity") {
				t.Fatalf("invalid validity accepted or issuance attempted: %v", err)
			}
		})
	}
}

func TestDNS01FallbackAttemptsHaveIndependentDeadlines(t *testing.T) {
	var calls int
	withStubOrder(t, func(ctx context.Context, _ DNS01Config, _ DNS01CA) error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 8*time.Minute || ctx.Err() != nil {
			t.Fatalf("attempt has no live bounded deadline: %v %v", deadline, ctx.Err())
		}
		return fmt.Errorf("failed")
	})
	_ = runDNS01Orders(context.Background(), DNS01Config{FallbackCAs: []DNS01CA{{DirectoryURL: "backup"}}})
	if calls != 2 {
		t.Fatalf("expected both attempts, got %d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = runDNS01Orders(ctx, DNS01Config{FallbackCAs: []DNS01CA{{DirectoryURL: "backup"}}})
	if calls != 2 {
		t.Fatal("canceled parent started another CA attempt")
	}
}
