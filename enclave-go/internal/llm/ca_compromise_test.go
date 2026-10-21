package llm

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidTLSStillAcceptedAfterCADistrust(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("valid TLS must remain usable: %v", err)
	}
	response.Body.Close()
}

// Use the old roots deliberately: rejection must come from the Go verifier's
// compromised-key block, even on hosts whose root bundles have not refreshed.
func TestEMudhraCompromisedChainsRejected(t *testing.T) {
	dir := filepath.Join("testdata", "emudhra")
	rootData, err := os.ReadFile(filepath.Join(dir, "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	var publishedRoots []struct{ PEM string }
	if err := json.Unmarshal(rootData, &publishedRoots); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	for _, root := range publishedRoots {
		if !roots.AppendCertsFromPEM([]byte(root.PEM)) {
			t.Fatal("invalid public root fixture")
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil || len(files) != 12 {
		t.Fatalf("expected all 12 compromised TLS chains: %d, %v", len(files), err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var chain []*x509.Certificate
			for len(data) > 0 {
				block, rest := pem.Decode(data)
				if block == nil {
					t.Fatal("invalid public certificate fixture")
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				chain = append(chain, cert)
				data = rest
			}
			if len(chain) < 2 {
				t.Fatal("fixture is missing its intermediate")
			}
			host := strings.TrimSuffix(filepath.Base(file), ".pem")
			if err := chain[0].VerifyHostname(host); err != nil {
				t.Fatal(err)
			}
			when := chain[0].NotBefore.Add(time.Hour)
			intermediates := x509.NewCertPool()
			for i, cert := range chain {
				if when.Before(cert.NotBefore) || !when.Before(cert.NotAfter) {
					t.Fatal("fixture is not valid at the frozen verification time")
				}
				if i > 0 {
					intermediates.AddCert(cert)
					if err := chain[i-1].CheckSignatureFrom(cert); err != nil {
						t.Fatalf("fixture has a broken signature, not a trust failure: %v", err)
					}
				}
			}
			if _, err := chain[0].Verify(x509.VerifyOptions{
				DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: when,
			}); err == nil {
				t.Fatal("compromised CA accepted; rebuild with Go 1.26.10 or newer")
			}
		})
	}
}
