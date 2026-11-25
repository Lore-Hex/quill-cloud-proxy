package main

import (
	"fmt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/authcache"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Captured before adding the route. Only the generated correlation ID varies.
func TestRerankOffPins(t *testing.T) {
	t.Setenv("TR_RERANK_ENABLED", "false")
	old := rerankEnabled
	rerankEnabled = false
	t.Cleanup(func() { rerankEnabled = old })
	for _, method := range []string{"POST", "GET", "PUT", "OPTIONS"} {
		for _, key := range []string{"none", "bad", "valid"} {
			t.Run(method+"_"+key, func(t *testing.T) {
				header := ""
				if key != "none" {
					header = "Authorization: Bearer " + key + "\r\n"
				}
				raw := fmt.Sprintf("%s /v1/rerank HTTP/1.1\r\nHost: api.trustedrouter.com\r\n%sConnection: close\r\nContent-Length: 2\r\n\r\n{}", method, header)
				conn := newScriptedConn(raw, nil)
				registry := auth.New([]types.DeviceConfig{{KeyHash: trustedrouter.LookupHash("valid")}})
				serveOne(t.Context(), conn, registry, nil, nil, nil, nil, nil)
				got := regexp.MustCompile(`rlog_[0-9a-f]{32}`).ReplaceAllString(conn.writes.String(), "rlog_00000000000000000000000000000000")
				path := filepath.Join("testdata", "rerank_off", method+"_"+key+".http")
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if got != string(want) {
					t.Fatalf("response changed: %q, want %q", got, want)
				}
			})
		}
	}
}

func TestRerankOffControlPlanePins(t *testing.T) {
	old := rerankEnabled
	rerankEnabled = false
	t.Cleanup(func() { rerankEnabled = old })
	for _, method := range []string{"POST", "GET", "PUT", "OPTIONS"} {
		for _, key := range []string{"none", "bad", "valid", "unseen"} {
			t.Run(method+"_"+key, func(t *testing.T) {
				calls := make(map[string][]map[string]any)
				gateway := rerankMemoryGateway(t, "success", &calls)
				gateway.SetCredentialGuard(abuse.NewProtector(authcache.New(time.Minute, 16), nil))
				if key == "bad" {
					gateway.ObserveCredentialResult(t.Context(), key, &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key", Message: "Invalid API key"})
				}
				header := ""
				if key != "none" {
					header = "Authorization: Bearer " + key + "\r\n"
				}
				conn := newScriptedConn(fmt.Sprintf("%s /v1/rerank HTTP/1.1\r\nHost: api.trustedrouter.com\r\n%sConnection: close\r\nContent-Length: 2\r\n\r\n{}", method, header), nil)
				serveOne(t.Context(), conn, auth.New(nil), nil, nil, nil, gateway, nil)
				got := regexp.MustCompile(`rlog_[0-9a-f]{32}`).ReplaceAllString(conn.writes.String(), "rlog_00000000000000000000000000000000")
				fixtureKey := key
				if key == "unseen" {
					fixtureKey = "valid"
				}
				want, err := os.ReadFile(filepath.Join("testdata", "rerank_off", method+"_"+fixtureKey+".http"))
				if err != nil {
					t.Fatal(err)
				}
				if got != string(want) {
					t.Fatalf("control-plane off response changed: %q want %q", got, want)
				}
				if len(calls["/internal/gateway/authorize"]) != 0 {
					t.Fatal("disabled route authorized")
				}
			})
		}
	}
}
