package main

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// The declaration follows the same flag that gates the heartbeats
// (stageDStreamEligible), so a boot declares exactly what it does.
func TestStageDBootDeclaresUsageHeartbeatExactlyWhenItHeartbeats(t *testing.T) {
	for _, tc := range []struct {
		flag     string
		declared bool
	}{{"on", true}, {"true", true}, {"", false}, {"off", false}} {
		t.Run("flag="+tc.flag, func(t *testing.T) {
			t.Setenv("QUILL_USAGE_HEARTBEAT", tc.flag)
			config := stageDConfigFromEnv()
			signer, err := receipt.NewSigner()
			if err != nil {
				t.Fatal(err)
			}
			posted := make(chan []byte, 1)
			gateway := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(request.Body)
				select {
				case posted <- body:
				default:
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request, Body: io.NopCloser(strings.NewReader(`{"data":{"verified":true}}`))}, nil
			})})
			declareStageDBootCapabilities(gateway, config, false)
			gateway.StartStageDBootRegistration(t.Context(), signer, func() trustedrouter.BootRegistrationEvidence {
				return trustedrouter.BootRegistrationEvidence{Attestation: "evidence", AttestationKind: "gcp-cs-jwt"}
			})
			var body []byte
			select {
			case body = <-posted:
			case <-time.After(5 * time.Second):
				t.Fatal("boot registration was not posted")
			}
			var decoded struct {
				Capabilities *struct {
					UsageHeartbeat bool `json:"usage_heartbeat"`
				} `json:"capabilities"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			got := decoded.Capabilities != nil && decoded.Capabilities.UsageHeartbeat
			if got != tc.declared || got != config.usageHeartbeat {
				t.Fatalf("declared usage_heartbeat=%t, heartbeats=%t, want %t: %s", got, config.usageHeartbeat, tc.declared, body)
			}
		})
	}
}

// main must declare before it starts any registration: the registration
// goroutines read the declaration once per payload, and a registration that
// omits it withdraws it on the control plane.
func TestMainDeclaresBootCapabilitiesBeforeAnyBootRegistration(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mainFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			mainFunc = fn
		}
	}
	if mainFunc == nil {
		t.Fatal("func main not found in main.go")
	}
	var declares []token.Pos
	registrations := map[string][]token.Pos{}
	ast.Inspect(mainFunc.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		switch name {
		case "declareStageDBootCapabilities":
			declares = append(declares, call.Pos())
		case "initializeSpendLeaseShadow", "StartStageDBootRegistration", "StartSpendLeaseBootRegistration":
			registrations[name] = append(registrations[name], call.Pos())
		}
		return true
	})
	if len(declares) != 1 {
		t.Fatalf("main declares boot capabilities %d times, want exactly once", len(declares))
	}
	// Positive control: the registrations this test orders must still exist.
	for _, name := range []string{"initializeSpendLeaseShadow", "StartStageDBootRegistration"} {
		if len(registrations[name]) == 0 {
			t.Fatalf("main no longer calls %s; update this test", name)
		}
	}
	for name, positions := range registrations {
		for _, pos := range positions {
			if pos < declares[0] {
				t.Fatalf("%s at %s runs before the boot capabilities are declared at %s", name, fset.Position(pos), fset.Position(declares[0]))
			}
		}
	}
}

// settle_outbox is declared exactly when this boot will park terminals: a
// bucket is set and this build can write to it. A boot that cannot park
// never claims it.
func TestStageDBootDeclaresSettleOutboxExactlyWhenItCanPark(t *testing.T) {
	store := func(string) (settleoutbox.Store, error) { return newOutboxTestStore(), nil }
	noStore := func(string) (settleoutbox.Store, error) { return nil, errors.New("unsupported_cloud") }
	for _, tc := range []struct {
		name     string
		bucket   string
		newStore func(string) (settleoutbox.Store, error)
		declared bool
	}{
		{"bucket_and_store", "outbox-bucket", store, true},
		{"no_bucket", "", store, false},
		{"bucket_no_store", "outbox-bucket", noStore, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QUILL_USAGE_HEARTBEAT", "")
			plan := prepareSettleOutbox(tc.bucket, tc.newStore)
			if plan.Configured() != tc.declared {
				t.Fatalf("Configured = %t, want %t", plan.Configured(), tc.declared)
			}
			signer, err := receipt.NewSigner()
			if err != nil {
				t.Fatal(err)
			}
			posted := make(chan []byte, 1)
			gateway := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(request.Body)
				select {
				case posted <- body:
				default:
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request, Body: io.NopCloser(strings.NewReader(`{"data":{"verified":true}}`))}, nil
			})})
			declareStageDBootCapabilities(gateway, stageDConfigFromEnv(), plan.Configured())
			gateway.StartStageDBootRegistration(t.Context(), signer, func() trustedrouter.BootRegistrationEvidence {
				return trustedrouter.BootRegistrationEvidence{Attestation: "evidence", AttestationKind: "gcp-cs-jwt"}
			})
			var body []byte
			select {
			case body = <-posted:
			case <-time.After(5 * time.Second):
				t.Fatal("boot registration was not posted")
			}
			var decoded struct {
				Capabilities map[string]json.RawMessage `json:"capabilities"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if got := string(decoded.Capabilities["settle_outbox"]); (got == "true") != tc.declared || (tc.declared && len(decoded.Capabilities) != 1) || (!tc.declared && decoded.Capabilities != nil) {
				t.Fatalf("declared settle_outbox=%q, want declared=%t: %s", got, tc.declared, body)
			}
		})
	}
}
