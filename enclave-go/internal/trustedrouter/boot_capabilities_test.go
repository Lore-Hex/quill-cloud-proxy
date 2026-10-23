package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

// bootCapabilitiesFixtureSeed derives the public test key in
// testdata/stage_d/boot_registration_*.json. It signs nothing real.
var bootCapabilitiesFixtureSeed = bytes.Repeat([]byte{0x07}, 32)

// firstRegistrationBody starts a boot registration on the given path and
// returns the first registration body it posts.
func firstRegistrationBody(t *testing.T, capabilities *BootCapabilities, start registrationPath) []byte {
	t.Helper()
	signer, err := receipt.NewSignerFromSeed(bootCapabilitiesFixtureSeed)
	if err != nil {
		t.Fatal(err)
	}
	posted := make(chan []byte, 1)
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != spendlease.RegisterPath {
			t.Errorf("path = %q", request.URL.Path)
		}
		body, _ := io.ReadAll(request.Body)
		select {
		case posted <- body:
		default:
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: io.NopCloser(strings.NewReader(`{"data":{"verified":true}}`)),
		}, nil
	})})
	if capabilities != nil {
		client.DeclareBootCapabilities(*capabilities)
	}
	start(t.Context(), client, signer)
	select {
	case body := <-posted:
		return body
	case <-time.After(5 * time.Second):
		t.Fatal("boot registration was not posted")
		return nil
	}
}

func evidence() BootRegistrationEvidence {
	return BootRegistrationEvidence{Attestation: "evidence", AttestationKind: "gcp-cs-jwt"}
}

// Every registration path a boot can run: Stage D (heartbeats on, or
// speculation shadow) and spend-lease (shadow or local admission).
type registrationPath func(context.Context, *Client, *receipt.Signer)

var registrationPaths = map[string]registrationPath{
	"stage_d": func(ctx context.Context, client *Client, signer *receipt.Signer) {
		client.StartStageDBootRegistration(ctx, signer, evidence)
	},
	"spend_lease": func(ctx context.Context, client *Client, signer *receipt.Signer) {
		client.ConfigureSpendLeaseShadow(signer, nil)
		client.StartSpendLeaseBootRegistration(ctx, signer, evidence)
	},
}

// registrationFixture is a fixture body without the file's trailing newline.
func registrationFixture(t *testing.T, name string) []byte {
	t.Helper()
	return bytes.TrimSuffix(stageDFixture(t, name), []byte("\n"))
}

func TestBootRegistrationDeclaresUsageHeartbeatOnEveryPath(t *testing.T) {
	want := registrationFixture(t, "boot_registration_usage_heartbeat.json")
	for name, start := range registrationPaths {
		t.Run(name, func(t *testing.T) {
			body := firstRegistrationBody(t, &BootCapabilities{UsageHeartbeat: true}, start)
			if !bytes.Equal(body, want) {
				t.Fatalf("registration body:\n got %s\nwant %s", body, want)
			}
			// The control plane's GatewayBootCapabilities takes a JSON boolean
			// (StrictBool) under capabilities.usage_heartbeat; "true" or 1 is
			// refused. The stream-open heartbeat is not declared.
			var decoded struct {
				Capabilities map[string]json.RawMessage `json:"capabilities"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if string(decoded.Capabilities["usage_heartbeat"]) != "true" || len(decoded.Capabilities) != 1 {
				t.Fatalf("capabilities = %s", body)
			}
		})
	}
}

func TestBootRegistrationWithoutHeartbeatsKeepsLegacyBody(t *testing.T) {
	want := registrationFixture(t, "boot_registration_undeclared.json")
	for name, start := range registrationPaths {
		for label, capabilities := range map[string]*BootCapabilities{"never_declared": nil, "declared_off": {}} {
			t.Run(name+"/"+label, func(t *testing.T) {
				body := firstRegistrationBody(t, capabilities, start)
				if !bytes.Equal(body, want) {
					t.Fatalf("registration body:\n got %s\nwant %s", body, want)
				}
				var decoded map[string]json.RawMessage
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatal(err)
				}
				if _, ok := decoded["capabilities"]; ok || len(decoded) != 4 {
					t.Fatalf("undeclared registration changed shape: %s", body)
				}
			})
		}
	}
}
