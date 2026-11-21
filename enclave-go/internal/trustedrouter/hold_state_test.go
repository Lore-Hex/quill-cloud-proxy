package trustedrouter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// holdTestClient is a client whose control plane authorizes everything and
// answers settles and refunds with the given statuses (0 means 200).
func holdTestClient(t *testing.T, settleStatus, refundStatus int) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fail := func(status int) bool {
			if status == 0 {
				return false
			}
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"control plane says %d","type":"test"}}`, status)
			return true
		}
		switch request.URL.Path {
		case "/internal/gateway/authorize":
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":"m","endpoint_id":"e@p/prepaid","provider":"p","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
		case settlePath:
			if !fail(settleStatus) {
				_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":1}}`)
			}
		case refundPath:
			if !fail(refundStatus) {
				_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
			}
		default:
			t.Errorf("unexpected control-plane path %s", request.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return New(server.URL, "internal", server.Client())
}

func holdTestAuthorize(t *testing.T, client *Client) *Authorization {
	t.Helper()
	authorization, err := client.AuthorizeWithRoute(
		context.Background(), "test-key",
		&qtypes.OpenAIChatRequest{Model: "m", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "hi"}}},
		"chat.completions",
	)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return authorization
}

// A hold is unclosed from the authorize until a terminal is attempted. The
// attempt counts whether or not it succeeds: after a settle that failed the
// charge may have landed, so nothing may conclude that a refund is still owed.
func TestHoldIsUnclosedUntilATerminalIsAttempted(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		settleStatus, refundStatus int
		terminal                   func(*Client, *Authorization) error
		wantErr                    bool
	}{
		{name: "refund", terminal: func(c *Client, a *Authorization) error {
			return c.Refund(context.Background(), a, 502, "provider_error", 0.1, nil)
		}},
		{name: "refund that fails", refundStatus: 500, wantErr: true, terminal: func(c *Client, a *Authorization) error {
			return c.Refund(context.Background(), a, 502, "provider_error", 0.1, nil)
		}},
		{name: "settle", terminal: func(c *Client, a *Authorization) error {
			_, err := c.Settle(context.Background(), a, Usage{RequestID: "req_1", InputTokens: 1, OutputTokens: 1})
			return err
		}},
		// 409 is not retried in-call, so the failure is immediate.
		{name: "settle that fails", settleStatus: 409, wantErr: true, terminal: func(c *Client, a *Authorization) error {
			_, err := c.Settle(context.Background(), a, Usage{RequestID: "req_1", InputTokens: 1, OutputTokens: 1})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := holdTestClient(t, tc.settleStatus, tc.refundStatus)
			authorization := holdTestAuthorize(t, client)
			if !authorization.HoldUnclosed() {
				t.Fatal("a fresh authorization is not an unclosed hold")
			}
			if err := tc.terminal(client, authorization); (err != nil) != tc.wantErr {
				t.Fatalf("terminal error = %v, want error %t", err, tc.wantErr)
			}
			if authorization.HoldUnclosed() {
				t.Fatal("the hold still reads as unclosed after a terminal was attempted")
			}
		})
	}
}

// The streaming path refunds a copy of the authorization that names the
// selected route. The copy and the original are one hold.
func TestHoldStateIsSharedByCopiesOfAnAuthorization(t *testing.T) {
	client := holdTestClient(t, 0, 0)
	authorization := holdTestAuthorize(t, client)
	selected := *authorization
	selected.Model, selected.EndpointID = "selected", "selected@p/prepaid"
	if err := client.Refund(context.Background(), &selected, 499, "client_write_failed", 0.1, nil); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if authorization.HoldUnclosed() {
		t.Fatal("refunding a copy left the original reading as unclosed")
	}
}

func TestEmbeddingsAuthorizationIsATrackedHold(t *testing.T) {
	client := holdTestClient(t, 0, 0)
	authorization, err := client.AuthorizeEmbeddings(context.Background(), "test-key", &qtypes.EmbeddingRequest{Model: "m", Input: "hi"}, 1)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !authorization.HoldUnclosed() {
		t.Fatal("a fresh embeddings authorization is not an unclosed hold")
	}
}

// Nothing can tell whether a terminal is still owed for an authorization this
// client did not just receive from an authorize call (one rebuilt from a
// stored job, a compacted retry, a spend-lease plan before its reserve), so it
// never reads as unclosed and no caller refunds it on that basis.
func TestOnlyAnAuthorizeCallCreatesATrackedHold(t *testing.T) {
	var missing *Authorization
	if missing.HoldUnclosed() {
		t.Fatal("a nil authorization reads as an unclosed hold")
	}
	rebuilt := &Authorization{AuthorizationID: "auth_1", Model: "m", EndpointID: "e@p/prepaid"}
	if rebuilt.HoldUnclosed() {
		t.Fatal("an authorization that no authorize call returned reads as an unclosed hold")
	}
	// Terminals on an untracked authorization are harmless and stay untracked.
	client := holdTestClient(t, 0, 0)
	if err := client.Refund(context.Background(), rebuilt, 502, "provider_error", 0.1, nil); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if rebuilt.HoldUnclosed() {
		t.Fatal("refunding an untracked authorization made it read as unclosed")
	}
}

// A spend-lease admission holds nothing at the control plane until its reserve:
// the locally built plan is not a hold, the authorization the reserve returns
// is.
func TestSpendLeaseReserveReturnsATrackedHoldAndThePlanIsNotOne(t *testing.T) {
	ctx := fixedStageCContext()
	client, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", http.StatusOK, nil)
	req := stageCFixtureRequest()
	plan, err := client.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000))
	if err != nil || plan == nil || plan.Local == nil {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	if plan.Local.HoldUnclosed() {
		t.Fatal("the local plan reads as a hold before anything was reserved")
	}
	reserved, marked, err := client.ReserveSpendLeaseAdmission(ctx, plan, req)
	if err != nil || !marked {
		t.Fatalf("reserve: marked=%t err=%v", marked, err)
	}
	if !reserved.HoldUnclosed() {
		t.Fatal("the reserved authorization is not an unclosed hold")
	}
}
