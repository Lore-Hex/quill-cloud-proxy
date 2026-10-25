package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// The shape quill-router's classifier requires of a gateway-minted key
// (_GATEWAY_MINTED_IDEMPOTENCY_KEY); a mark on any other shape is legacy.
var gatewayMintedKeyShape = regexp.MustCompile(`^tr-gateway-[0-9a-f]{32}$`)

// authorizeCapture answers every authorize with the given statuses in turn
// (the last one repeats) and records the exact bytes and boot-auth header of
// each attempt.
type authorizeCapture struct {
	bodies   [][]byte
	bootAuth []string
}

func capturingAuthorizeClient(t *testing.T, statuses ...int) (*Client, *authorizeCapture) {
	t.Helper()
	capture := &authorizeCapture{}
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != spendlease.AuthorizePath {
			t.Errorf("path = %q", request.URL.Path)
		}
		body, _ := io.ReadAll(request.Body)
		capture.bodies = append(capture.bodies, body)
		capture.bootAuth = append(capture.bootAuth, request.Header.Get(spendlease.BootAuthHeader))
		status := statuses[len(statuses)-1]
		if attempt := len(capture.bodies) - 1; attempt < len(statuses) {
			status = statuses[attempt]
		}
		reply := `{"data":{"authorization_id":"auth_marked"}}`
		if status != http.StatusOK {
			reply = `{"error":{"message":"retry","type":"service_unavailable"}}`
		}
		return &http.Response{
			StatusCode: status, Header: make(http.Header), Request: request,
			Body: io.NopCloser(strings.NewReader(reply)),
		}, nil
	})})
	client.authorizeRetry = retryPolicy{attempts: 3, sleep: func(context.Context, time.Duration) error { return nil }}
	return client, capture
}

// decodedAuthorize is the one member under test plus the key it marks.
func decodedAuthorize(t *testing.T, body []byte) (key string, source json.RawMessage, marked bool) {
	t.Helper()
	var decoded struct {
		IdempotencyKey string          `json:"idempotency_key"`
		Source         json.RawMessage `json:"idempotency_key_source"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		t.Fatal(err)
	}
	_, marked = members["idempotency_key_source"]
	return decoded.IdempotencyKey, decoded.Source, marked
}

// A key the enclave minted is marked exactly "gateway" (a JSON string: the
// router bounds anything else to legacy) on every authorize entry point.
func TestAuthorizeMarksMintedIdempotencyKeyAsGateway(t *testing.T) {
	entries := map[string]func(*Client) error{
		"chat": func(client *Client) error {
			_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"})
			return err
		},
		"responses": func(client *Client) error {
			_, err := client.AuthorizeWithRoute(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"}, "responses")
			return err
		},
		"embeddings": func(client *Client) error {
			_, err := client.AuthorizeEmbeddings(t.Context(), "sk-test", &qtypes.EmbeddingRequest{Model: "trustedrouter/embed"}, 3)
			return err
		},
	}
	for name, authorize := range entries {
		t.Run(name, func(t *testing.T) {
			client, capture := capturingAuthorizeClient(t, http.StatusOK)
			if err := authorize(client); err != nil {
				t.Fatal(err)
			}
			if len(capture.bodies) != 1 {
				t.Fatalf("attempts = %d", len(capture.bodies))
			}
			key, source, marked := decodedAuthorize(t, capture.bodies[0])
			if !gatewayMintedKeyShape.MatchString(key) {
				t.Fatalf("minted key does not have the gateway shape")
			}
			if !marked || string(source) != `"gateway"` {
				t.Fatalf("idempotency_key_source = %s, want \"gateway\"", source)
			}
		})
	}
}

// A key the enclave was handed carries no mark at all (the router reads an
// absent field as legacy, today's treatment), whatever the key looks like:
// a caller cannot forge the mark by sending a key of the minted shape.
func TestAuthorizePassthroughIdempotencyKeyCarriesNoSourceMark(t *testing.T) {
	forged := "tr-gateway-" + strings.Repeat("0", 32)
	entries := map[string]func(*Client, string) error{
		"chat": func(client *Client, key string) error {
			_, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap", IdempotencyKey: key})
			return err
		},
		"embeddings": func(client *Client, key string) error {
			_, err := client.AuthorizeEmbeddings(t.Context(), "sk-test", &qtypes.EmbeddingRequest{Model: "trustedrouter/embed", IdempotencyKey: key}, 3)
			return err
		},
	}
	for name, authorize := range entries {
		for label, key := range map[string]string{"client_key": "client-chosen-key", "forged_shape": forged} {
			t.Run(name+"/"+label, func(t *testing.T) {
				client, capture := capturingAuthorizeClient(t, http.StatusOK)
				if err := authorize(client, key); err != nil {
					t.Fatal(err)
				}
				sent, source, marked := decodedAuthorize(t, capture.bodies[0])
				if sent != key {
					t.Fatalf("idempotency_key = %q, want the caller's", sent)
				}
				if marked {
					t.Fatalf("passthrough key marked idempotency_key_source=%s", source)
				}
			})
		}
	}
}

// Stage C mints the key and writes it back on the request before it can fall
// back to the ordinary authorize, so the record is the key itself: the
// fallback still marks it, and a copy that replaces the key (a fusion
// sub-request, a decide retry) does not.
func TestAuthorizeMarkFollowsTheMintedKeyAcrossTheStageCFallback(t *testing.T) {
	minted := "tr-gateway-" + strings.Repeat("ab", 16)
	fallback := &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap", IdempotencyKey: minted, MintedIdempotencyKey: minted}
	derived := *fallback
	derived.IdempotencyKey = minted + ":decide-retry-2"
	for label, tc := range map[string]struct {
		req    *qtypes.OpenAIChatRequest
		marked bool
	}{"fallback_reuses_minted_key": {fallback, true}, "copy_replaced_key": {&derived, false}} {
		t.Run(label, func(t *testing.T) {
			client, capture := capturingAuthorizeClient(t, http.StatusOK)
			if _, err := client.AuthorizeWithRoute(t.Context(), "sk-test", tc.req, "chat.completions"); err != nil {
				t.Fatal(err)
			}
			sent, source, marked := decodedAuthorize(t, capture.bodies[0])
			if sent != tc.req.IdempotencyKey {
				t.Fatalf("idempotency_key = %q, want %q", sent, tc.req.IdempotencyKey)
			}
			if marked != tc.marked || (marked && string(source) != `"gateway"`) {
				t.Fatalf("marked=%t source=%s, want marked=%t", marked, source, tc.marked)
			}
		})
	}
}

// Stage C's receipt-bearing body is an allow-list copy of the ordinary body;
// it carries the mark exactly when the ordinary body does, and the plan
// records the minted key on the request for the fallback.
func TestStageCAdmissionBodyCarriesTheMintedMark(t *testing.T) {
	c := &Client{region: "us-central1"}
	for _, minted := range []bool{false, true} {
		req := stageCFixtureRequest()
		ordinary := chatAuthorizeBody(c, stageCFixtureLookupHash, req.IdempotencyKey, minted, req, "chat.completions")
		body := admissionAuthorizeBody(c, stageCFixtureLookupHash, ordinary, &spendlease.Admission{Receipt: "receipt"})
		source, marked := body["idempotency_key_source"]
		if marked != minted || (minted && source != "gateway") {
			t.Fatalf("minted=%t: admission body idempotency_key_source=%v (present=%t)", minted, source, marked)
		}
	}

	req := stageCFixtureRequest()
	req.IdempotencyKey = ""
	client, _, _ := stageCAdmissionClientForRequest(t, "admission_accepted_response.json", http.StatusOK, nil, "chat.completions", req, nil)
	plan, err := client.PrepareSpendLeaseAdmission(fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000))
	if err != nil || plan == nil {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	defer plan.Cancel()
	if !gatewayMintedKeyShape.MatchString(req.IdempotencyKey) || req.MintedIdempotencyKey != req.IdempotencyKey || plan.key != req.IdempotencyKey {
		t.Fatalf("Stage C did not record the minted key on the request: key=%q minted=%q plan=%q", req.IdempotencyKey, req.MintedIdempotencyKey, plan.key)
	}
	key, source, marked := decodedAuthorize(t, plan.body)
	if key != plan.key || !marked || string(source) != `"gateway"` {
		t.Fatalf("frozen Stage C body: key=%q source=%s", key, source)
	}
}

// The mark is inside the bytes an authorize retry replays, byte for byte,
// and inside the boot-signed digest over them: the router fingerprints the
// body minus the field, so a retry that carried the field only on its second
// attempt would 409 on a router that does not know it.
func TestAuthorizeRetryReplaysTheMarkedBytesExactly(t *testing.T) {
	signer, err := receipt.NewSignerFromSeed(bootCapabilitiesFixtureSeed)
	if err != nil {
		t.Fatal(err)
	}
	client, capture := capturingAuthorizeClient(t, http.StatusServiceUnavailable, http.StatusOK)
	client.ConfigureStageDBoot(signer)
	if _, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "trustedrouter/cheap"}); err != nil {
		t.Fatal(err)
	}
	if len(capture.bodies) != 2 {
		t.Fatalf("attempts = %d, want 2", len(capture.bodies))
	}
	if !bytes.Equal(capture.bodies[0], capture.bodies[1]) {
		t.Fatalf("retry bytes differ:\nfirst  %s\nsecond %s", capture.bodies[0], capture.bodies[1])
	}
	if capture.bootAuth[0] == "" || capture.bootAuth[0] != capture.bootAuth[1] {
		t.Fatalf("boot auth differs across the retry: %q vs %q", capture.bootAuth[0], capture.bootAuth[1])
	}
	for attempt, body := range capture.bodies {
		if _, source, marked := decodedAuthorize(t, body); !marked || string(source) != `"gateway"` {
			t.Fatalf("attempt %d idempotency_key_source = %s", attempt+1, source)
		}
	}
	bootAuth, err := spendlease.SignAuthorize(signer, http.MethodPost, spendlease.AuthorizePath, capture.bodies[0])
	if err != nil {
		t.Fatal(err)
	}
	if bootAuth.HeaderValue() != capture.bootAuth[0] {
		t.Fatal("boot auth does not sign the marked bytes")
	}
}

// capabilities.idempotency_key_source rides next to the other declarations
// on every registration path, pinned to fixture bytes; the control plane's
// GatewayBootCapabilities takes a JSON boolean (StrictBool).
func TestBootRegistrationDeclaresIdempotencyKeySourceExactlyWhenDeclared(t *testing.T) {
	cases := []struct {
		fixture      string
		capabilities BootCapabilities
		want         map[string]string
	}{
		{"boot_registration_idempotency_key_source.json", BootCapabilities{IdempotencyKeySource: true}, map[string]string{"idempotency_key_source": "true"}},
		{"boot_registration_usage_heartbeat_idempotency_key_source_settle_outbox.json", BootCapabilities{UsageHeartbeat: true, IdempotencyKeySource: true, SettleOutbox: true}, map[string]string{"usage_heartbeat": "true", "idempotency_key_source": "true", "settle_outbox": "true"}},
		{"boot_registration_usage_heartbeat_settle_outbox.json", BootCapabilities{UsageHeartbeat: true, SettleOutbox: true}, map[string]string{"usage_heartbeat": "true", "settle_outbox": "true"}},
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
