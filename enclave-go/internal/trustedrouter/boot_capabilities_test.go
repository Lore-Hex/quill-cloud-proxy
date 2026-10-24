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

// settle_outbox (E4 E3) rides next to usage_heartbeat: declared alone, with
// heartbeats, and withdrawn when the outbox is off, on every registration
// path, pinned to fixture bytes.
func TestBootRegistrationDeclaresSettleOutboxExactlyWhenDeclared(t *testing.T) {
	cases := []struct {
		fixture      string
		capabilities BootCapabilities
		want         map[string]string
	}{
		{"boot_registration_settle_outbox.json", BootCapabilities{SettleOutbox: true}, map[string]string{"settle_outbox": "true"}},
		{"boot_registration_usage_heartbeat_settle_outbox.json", BootCapabilities{UsageHeartbeat: true, SettleOutbox: true}, map[string]string{"usage_heartbeat": "true", "settle_outbox": "true"}},
		{"boot_registration_usage_heartbeat.json", BootCapabilities{UsageHeartbeat: true}, map[string]string{"usage_heartbeat": "true"}},
		{"boot_registration_undeclared.json", BootCapabilities{}, nil},
	}
	for name, start := range registrationPaths {
		for _, tc := range cases {
			t.Run(name+"/"+tc.fixture, func(t *testing.T) {
				capabilities := tc.capabilities
				body := firstRegistrationBody(t, &capabilities, start)
				if want := registrationFixture(t, tc.fixture); !bytes.Equal(body, want) {
					t.Fatalf("registration body:\n got %s\nwant %s", body, want)
				}
				var decoded struct {
					Capabilities map[string]json.RawMessage `json:"capabilities"`
				}
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatal(err)
				}
				if len(decoded.Capabilities) != len(tc.want) {
					t.Fatalf("capabilities = %s, want %v", body, tc.want)
				}
				for key, value := range tc.want {
					if string(decoded.Capabilities[key]) != value {
						t.Fatalf("capabilities[%s] = %s, want %s", key, decoded.Capabilities[key], value)
					}
				}
			})
		}
	}
}

// RegisteredBootSigner is the key a registration path was started for, and
// nil for a boot that registers nowhere.
func TestRegisteredBootSignerFollowsTheRegistrationPaths(t *testing.T) {
	signer, err := receipt.NewSignerFromSeed(bootCapabilitiesFixtureSeed)
	if err != nil {
		t.Fatal(err)
	}
	var nilClient *Client
	if nilClient.RegisteredBootSigner() != nil {
		t.Fatal("nil client has a registered signer")
	}
	client := New("http://127.0.0.1:18080", "internal", &http.Client{})
	if client.RegisteredBootSigner() != nil {
		t.Fatal("unregistered boot has a registered signer")
	}
	client.ConfigureStageDBoot(signer)
	if got := client.RegisteredBootSigner(); got == nil || got.Kid() != signer.Kid() {
		t.Fatalf("stage D signer = %v", got)
	}
	spendLease := New("http://127.0.0.1:18080", "internal", &http.Client{})
	spendLease.ConfigureSpendLeaseShadow(signer, nil)
	if got := spendLease.RegisteredBootSigner(); got == nil || got.Kid() != signer.Kid() {
		t.Fatalf("spend-lease signer = %v", got)
	}
	shadow := New("http://127.0.0.1:18080", "internal", &http.Client{})
	shadow.ConfigureShadowBoot(signer)
	if got := shadow.RegisteredBootSigner(); got == nil || got.Kid() != signer.Kid() {
		t.Fatalf("shadow signer = %v", got)
	}
}
