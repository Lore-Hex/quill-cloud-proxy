//go:build cloud_aws

package enclavetls

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type claimTransport func(*http.Request) (*http.Response, error)

func (f claimTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type claimTokens struct{}

func (claimTokens) Token(context.Context) (string, error) { return "fixture", nil }

type failDNSCleanup struct{ recordingProvider }

func (p *failDNSCleanup) RemoveTXT(ctx context.Context, id string) error {
	_ = p.recordingProvider.RemoveTXT(ctx, id)
	return errors.New("fixture: deletion uncertain")
}

func TestNitroFirstOrderRequiresPublicTXTAndCleanup(t *testing.T) {
	for _, visible := range []bool{false, true} {
		t.Run(fmt.Sprint(visible), func(t *testing.T) {
			var accepted, proofs atomic.Int32
			ca := fakeACMEWith(t, func(w http.ResponseWriter, r *http.Request, base string) bool {
				switch {
				case r.URL.Path == "/chal/1":
					accepted.Add(1)
					fmt.Fprintf(w, `{"type":"dns-01","url":%q,"status":"valid","token":"tok"}`, base+"/chal/1")
				case r.URL.Path == "/authz/1" && accepted.Load() > 0:
					fmt.Fprint(w, `{"status":"valid","identifier":{"type":"dns","value":"api-aws.trustedrouter.com"}}`)
				default:
					return false
				}
				return true
			})
			prev, prevUDP := preissuePublicTXT, resolverTXTWait
			t.Cleanup(func() { preissuePublicTXT, resolverTXTWait = prev, prevUDP })
			resolverTXTWait = func(context.Context, string, string) error { t.Fatal("Nitro attempted UDP"); return nil }
			preissuePublicTXT = func(_ context.Context, since time.Time, owner, target, token string) error {
				proofs.Add(1)
				if since.IsZero() || owner != "_acme-challenge."+NitroGatewayHost || target != owner || token == "" {
					t.Fatal("wrong public TXT binding")
				}
				if !visible {
					return errors.New("not publicly visible")
				}
				return nil
			}
			provider := &failDNSCleanup{recordingProvider: recordingProvider{waitErr: errors.New("changes.get denied")}}
			cache := autocert.DirCache(t.TempDir())
			err := PreissueDNS01(t.Context(), DNS01Config{nitroFirstOrder: true, DNSName: NitroGatewayHost, Cache: cache, Provider: provider, DirectoryURL: ca.URL + "/directory", HTTPClient: ca.Client()}, false)
			if err == nil || (visible && !strings.Contains(err.Error(), "cleanup not confirmed")) || proofs.Load() != 1 || (accepted.Load() == 1) != visible || len(provider.removed) != 1 {
				t.Fatalf("err=%v proofs=%d accepts=%d deletes=%d", err, proofs.Load(), accepted.Load(), len(provider.removed))
			}
			if _, err := cache.Get(t.Context(), NitroGatewayHost); !errors.Is(err, autocert.ErrCacheMiss) {
				t.Fatal("published unqualified leaf")
			}
		})
	}
}

func TestNitroOrderFencedAcrossReplicasAndAmbiguousResults(t *testing.T) {
	for _, mode := range []string{"parallel", "lost-response", "not-armed", "bad-permit", "expired", "too-long", "cache-error", "cached", "failed-order"} {
		t.Run(mode, func(t *testing.T) {
			var writes, orders atomic.Int32
			var claimed, ready atomic.Bool
			store := &gcsCache{bucket: AWSSealedBucket, tokens: claimTokens{}, httpClient: &http.Client{Transport: claimTransport(func(r *http.Request) (*http.Response, error) {
				body, status := "", 200
				switch r.Method {
				case http.MethodGet:
					if r.URL.String() != gcsAPIBase+"/b/"+AWSSealedBucket+"/o/"+url.PathEscape(firstOrderPrefix+"permit")+"?alt=media" {
						t.Error("wrong permit object")
					}
					expiry := time.Now().Add(20 * time.Minute)
					if mode == "expired" {
						expiry = time.Now().Add(-time.Minute)
					}
					if mode == "too-long" {
						expiry = time.Now().Add(time.Hour)
					}
					body = "first-order-v1 " + NitroGatewayHost + " fixture-pin " + expiry.UTC().Format(time.RFC3339) + "\n"
					if mode == "bad-permit" {
						body += "x"
					}
					if mode == "not-armed" {
						status = 404
					}
				case http.MethodPost:
					if r.URL.Path != "/upload/storage/v1/b/"+AWSSealedBucket+"/o" || r.URL.Query().Get("name") != firstOrderPrefix+"claimed" || r.URL.Query().Get("ifGenerationMatch") != "0" {
						t.Error("unfenced order claim")
					}
					writes.Add(1)
					if !claimed.CompareAndSwap(false, true) {
						status = 412
					} else if mode == "lost-response" {
						return nil, errors.New("synthetic lost response after write")
					}
				default:
					t.Error("unexpected method")
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := ensureNitroLeaf(t.Context(), func(context.Context) error {
						if mode == "cache-error" {
							return errors.New("uncertain read")
						}
						if mode == "cached" || ready.Load() {
							return nil
						}
						return autocert.ErrCacheMiss
					}, func(ctx context.Context) error { return claimNitroOrder(ctx, store, "fixture-pin") }, func(context.Context) error {
						orders.Add(1)
						if mode == "failed-order" {
							return errors.New("ambiguous order")
						}
						ready.Store(true)
						return nil
					})
					if err == nil && mode != "parallel" && mode != "cached" {
						t.Error("failed case reported ready")
					}
				}()
			}
			wg.Wait()
			expected := int32(0)
			if mode == "parallel" || mode == "failed-order" {
				expected = 1
			}
			if orders.Load() != expected {
				t.Fatalf("got %d orders, want %d", orders.Load(), expected)
			}
			if (mode == "cached" || mode == "not-armed" || mode == "bad-permit" || mode == "expired" || mode == "too-long" || mode == "cache-error") && writes.Load() != 0 {
				t.Fatal("unexpected claim write")
			}
			if mode == "lost-response" && !claimed.Load() {
				t.Fatal("did not exercise ambiguous write")
			}
		})
	}
}

func TestNitroServingLeafVerifiesHostnameTrustAndPair(t *testing.T) {
	ctx := t.Context()
	c := autocert.DirCache(t.TempDir())
	if err := verifiedNitroLeaf(ctx, c, nil); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatal(err)
	}
	for _, host := range []string{NitroGatewayHost, "wrong.example"} {
		s, err := NewSelfSigned(host)
		if err != nil {
			t.Fatal(err)
		}
		pair := s.Certificate
		b, err := encodeAutocertEntry(pair.PrivateKey.(*ecdsa.PrivateKey), pair.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Put(ctx, NitroGatewayHost, b); err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if verifiedNitroLeaf(ctx, c, roots) == nil {
			t.Fatal("accepted untrusted leaf")
		}
		roots.AddCert(pair.Leaf)
		if err = verifiedNitroLeaf(ctx, c, roots); (err == nil) != (host == NitroGatewayHost) {
			t.Fatalf("host=%s: %v", host, err)
		}
	}
	if err := c.Put(ctx, NitroGatewayHost, []byte("not a certificate")); err != nil {
		t.Fatal(err)
	}
	if err := verifiedNitroLeaf(ctx, c, nil); err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatal("treated corrupt cache as absent")
	}
}
