package llm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFortanixGatesInferenceOnActualConn(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{fortanixAuthority}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, scenario := range []string{"pass", "refused", "cancelled", "close", "redirect", "oversize", "wrong path", "wrong host", "plaintext"} {
		t.Run(scenario, func(t *testing.T) {
			var gets, posts, dials atomic.Int32
			var allowed atomic.Bool
			var first atomic.Value
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					gets.Add(1)
					first.Store(r.RemoteAddr)
					q := r.URL.Query()
					if r.Host != fortanixAuthority || r.URL.Path != "/v1/attestation/report" || q.Get("version") != "2" || q.Get("model") != fortanixNativeModel || len(q.Get("nonce")) != 64 || r.Header.Get("Authorization") != "Bearer test" {
						t.Error("wrong report request")
					}
					switch scenario {
					case "close":
						w.Header().Set("Connection", "close")
					case "redirect":
						w.WriteHeader(307)
						return
					case "oversize":
						fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
						return
					}
					fmt.Fprint(w, q.Get("nonce"))
					return
				}
				if r.Method != "POST" || !allowed.Load() || first.Load() != r.RemoteAddr {
					t.Error("inference was not on the attested channel")
				}
				posts.Add(1)
				w.WriteHeader(204)
			}))
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}, MinVersion: tls.VersionTLS13}
			srv.StartTLS()
			defer srv.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := fortanixAttestedClient("test", func(ctx context.Context, network, addr string) (*tls.Conn, error) {
				dials.Add(1)
				d := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: fortanixAuthority, MinVersion: tls.VersionTLS13}}
				c, e := d.DialContext(ctx, network, srv.Listener.Addr().String())
				if e != nil {
					return nil, e
				}
				return c.(*tls.Conn), nil
			}, func(_ context.Context, proof []byte, n, s [32]byte) error {
				if s != sha256.Sum256(leaf.RawSubjectPublicKeyInfo) || string(proof) != hex.EncodeToString(n[:]) || n == [32]byte{} {
					t.Error("wrong binding")
				}
				if scenario == "refused" {
					return errors.New("declined")
				}
				if scenario == "cancelled" {
					cancel()
					return ctx.Err()
				}
				allowed.Store(true)
				return nil
			})
			url := "https://" + fortanixAuthority + "/v1/chat/completions"
			switch scenario {
			case "wrong host":
				url = "https://example.invalid/v1/chat/completions"
			case "wrong path":
				url += "extra"
			case "plaintext":
				url = strings.Replace(url, "https:", "http:", 1)
			}
			send := func() error {
				req, e := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(`{"model":"GLM-5.3-Flash","messages":[]}`))
				if e != nil {
					return e
				}
				res, e := client.Do(req)
				if res != nil {
					res.Body.Close()
				}
				return e
			}
			e := send()
			if (e == nil) != (scenario == "pass") {
				t.Fatalf("unexpected result %v", e)
			}
			if scenario == "pass" && send() == nil {
				t.Fatal("accepted a second inference")
			}
			wantGets, wantPosts := int32(1), int32(0)
			if scenario == "pass" {
				wantPosts = 1
			}
			if scenario == "wrong path" || scenario == "wrong host" || scenario == "plaintext" {
				wantGets = 0
			}
			if dials.Load() != wantGets || gets.Load() != wantGets || posts.Load() != wantPosts {
				t.Errorf("observed %d dials, %d proofs, %d inferences", dials.Load(), gets.Load(), posts.Load())
			}
		})
	}
}

func TestFortanixOnlySendsTheBoundModel(t *testing.T) {
	for _, wire := range []string{`{}`, `{"model":"other"}`, `{"MODEL":"GLM-5.3-Flash"}`, `{"model":"other","model":"GLM-5.3-Flash"}`, `{"model":"GLM-5.3-Flash"}{}`, `{"model":null}`} {
		req, err := http.NewRequest("POST", "https://"+fortanixAuthority+"/v1/chat/completions", strings.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if fortanixPinWireModel(req) == nil {
			t.Fatal("accepted ambiguous or unqualified model")
		}
	}
}
