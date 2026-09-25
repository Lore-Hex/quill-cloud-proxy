package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Literal router serialization, including its stored null invocation nonce.
// Sources: router gateway.py:1366-1405,3036-3062 and
// storage_gcp_authorize.py:465-498; see testdata/stage_c_replay_response.md.
func stageCReplayFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/stage_c_replay_response.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func replayResponse(r *http.Request, b []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Request: r, Body: io.NopCloser(bytes.NewReader(b))}
}

func prepareReplayPlan(t *testing.T, c *Client, ctx context.Context) (*SpendLeaseAdmissionPlan, *qtypes.OpenAIChatRequest) {
	t.Helper()
	req := stageCFixtureRequest()
	p, err := c.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000))
	if err != nil || p == nil {
		t.Fatalf("prepare: plan=%v error=%v", p, err)
	}
	return p, req
}

func requireReplayError(t *testing.T, err error, status int, kind, reason string) {
	t.Helper()
	var ce *ControlPlaneError
	if !errors.As(err, &ce) || ce.StatusCode != status || ce.Type != kind || ce.Reason != reason {
		t.Fatalf("error=%#v, want %d %s/%s", err, status, kind, reason)
	}
}

type lostAckBody struct{}

func (lostAckBody) Read([]byte) (int, error) { return 0, syscall.ECONNRESET }

func TestStageCReserveCommitThenResponseLostRouterReplay(t *testing.T) {
	for _, boundary := range []string{"before_headers", "body_read_reset"} {
		t.Run(boundary, func(t *testing.T) {
			// The first authority is undialable; a lost acknowledgement at the second
			// must pin retries AND finalization there even if the primary recovers.
			c, signer, claims := stageCAdmissionClient(t, "admission_accepted_response.json", 200, nil)
			c.baseURLs = []string{"http://authority-primary", "http://authority-committed"}
			c.authorizeRetry = retryPolicy{attempts: 2, sleep: func(context.Context, time.Duration) error { return nil }}
			observed := &observedStageCSigner{Signer: signer}
			c.spendLease.signer = observed
			before := stageCCapacity(t, c)
			ctx := fixedStageCContext()
			p, req := prepareReplayPlan(t, c, ctx)
			afterPrepare := stageCCapacity(t, c)
			if before != claims.CapMicro || afterPrepare != before-p.admission.EstimateMicro || observed.messages.Load() != 1 || observed.digests.Load() != 0 {
				t.Fatalf("prepare capacity/signing: before=%d after=%d estimate=%d receipt=%d boot=%d", before, afterPrepare, p.admission.EstimateMicro, observed.messages.Load(), observed.digests.Load())
			}
			checkRetryState := func() {
				t.Helper()
				if remaining := stageCCapacity(t, c); remaining != afterPrepare || observed.messages.Load() != 1 || observed.digests.Load() != 1 {
					t.Fatalf("retry spent capacity or re-signed: remaining=%d want=%d receipt=%d boot=%d", remaining, afterPrepare, observed.messages.Load(), observed.digests.Load())
				}
			}
			var firstBody []byte
			var firstProof string
			allocations, attempts, finalizations := 0, 0, 0
			var committedID string
			c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				if r.URL.Host == "authority-primary" {
					if attempts > 0 {
						t.Fatal("retry/finalize escaped committed authority")
					}
					return nil, &dialFailure{err: errors.New("connection refused")}
				}
				if r.URL.Path == spendlease.AuthorizePath {
					checkRetryState()
					attempts++
					if attempts == 1 {
						if !bytes.Equal(b, stageCFixture(t, "receipt_bearing_authorize_request.json")) {
							t.Fatalf("noncanonical reserve: %s", b)
						}
						firstBody = append([]byte(nil), b...)
						firstProof = r.Header.Get(spendlease.BootAuthHeader)
						allocations++
						committedID = "gwa-stage-c-fixture"
						// Commit, then lose the acknowledgement at the selected boundary.
						if boundary == "body_read_reset" {
							response := replayResponse(r, nil)
							response.Body = io.NopCloser(lostAckBody{})
							return response, nil
						}
						return nil, io.ErrUnexpectedEOF
					}
					if !bytes.Equal(b, firstBody) || firstProof == "" || firstProof != r.Header.Get(spendlease.BootAuthHeader) {
						t.Fatal("retry body/proof changed")
					}
					return replayResponse(r, stageCReplayFixture(t)), nil
				}
				if r.URL.Path != "/internal/gateway/settle" {
					t.Fatalf("unexpected finalization: %s", r.URL.Path)
				}
				var body map[string]any
				if err := json.Unmarshal(b, &body); err != nil {
					t.Fatal(err)
				}
				if body["authorization_id"] != committedID {
					t.Fatalf("settled wrong authorization: %s", b)
				}
				finalizations++
				return replayResponse(r, []byte(`{"data":{"settled":true}}`)), nil
			})
			// The chat-handler regression separately verifies actual provider execution.
			a, marked, err := c.ReserveSpendLeaseAdmission(ctx, p, req)
			if err != nil || !marked || a == nil || a.AuthorizationID != committedID || !a.IdempotentReplay || a.InvocationNonce != "" {
				t.Fatalf("lost ack: auth=%v marked=%v err=%v", a, marked, err)
			}
			checkRetryState()
			if !a.ControlPlaneEndpointSet || a.ControlPlaneEndpoint != 1 {
				t.Fatalf("wrong authority: %+v", a)
			}
			if _, err := c.Settle(ctx, a, Usage{InputTokens: 100, OutputTokens: 1}); err != nil {
				t.Fatal(err)
			}
			_, _, err = c.ReserveSpendLeaseAdmission(ctx, p, req)
			requireReplayError(t, err, 409, "idempotency_replay", "idempotency_replay")
			if allocations != 1 || attempts != 2 || finalizations != 1 {
				t.Fatalf("allocate/attempt/finalize=%d/%d/%d", allocations, attempts, finalizations)
			}
		})
	}
}

func TestStageCPlanOwnershipAndTombstones(t *testing.T) {
	for _, name := range []string{"no_invocation", "changed_key", "different_client", "different_invocation_same_nonce", "copied_plan", "reconstructed_receipt", "consumed_claim", "cancelled", "repeat_prepare", "ordinary_cannot_claim_plan", "frozen_request", "frozen_local"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", 200, func(_ *http.Request, b []byte) {
				calls++
				if name == "frozen_request" && !bytes.Equal(b, stageCFixture(t, "receipt_bearing_authorize_request.json")) {
					t.Fatal("request was not frozen")
				}
			})
			ctx := fixedStageCContext()
			if name == "no_invocation" {
				noOwner, err := WithAPIKeyLookupHash(context.Background(), stageCFixtureLookupHash)
				if err != nil {
					t.Fatal(err)
				}
				p, err := c.PrepareSpendLeaseAdmission(noOwner, "sk-stage-c-fixture", stageCFixtureRequest(), "chat.completions", time.UnixMilli(2_000_000_005_000))
				if p != nil || err != nil {
					t.Fatalf("scope-less prepare: plan=%v err=%v", p, err)
				}
				return
			}
			p, req := prepareReplayPlan(t, c, ctx)
			var err error
			switch name {
			case "changed_key":
				req.IdempotencyKey = "other"
			case "different_client":
				other := New(c.baseURLs[0], c.internalToken, c.httpc)
				other.region = c.region
				other.spendLease = c.spendLease
				c = other
			case "different_invocation_same_nonce":
				ctx = fixedStageCContext()
			case "copied_plan":
				copy := *p
				p = &copy
			case "reconstructed_receipt":
				p = &SpendLeaseAdmissionPlan{admission: p.admission, Local: p.Local}
			case "consumed_claim":
				if !p.owner.claimPlan(p.key, p) {
					t.Fatal("initial claim failed")
				}
			case "cancelled":
				p.Cancel()
			case "repeat_prepare":
				p.Cancel()
				_, err = c.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_006_000))
			case "ordinary_cannot_claim_plan":
				_, err = c.AuthorizeWithRoute(ctx, "sk-stage-c-fixture", req, "chat.completions")
			case "frozen_request":
				req.Model = "rewritten-provider-model"
				req.Provider.Only[0] = "rewritten-provider"
			case "frozen_local":
				p.Local.UpstreamModel = "mutated"
				p.Local.RouteCandidates[0].UpstreamModel = "mutated"
			}
			if name != "repeat_prepare" && name != "ordinary_cannot_claim_plan" {
				_, _, err = c.ReserveSpendLeaseAdmission(ctx, p, req)
			}
			if name == "frozen_request" || name == "frozen_local" {
				if err != nil || calls != 1 {
					t.Fatalf("frozen plan: calls=%d err=%v", calls, err)
				}
				return
			}
			requireReplayError(t, err, 409, "idempotency_replay", "idempotency_replay")
			want := 0
			if name == "ordinary_cannot_claim_plan" {
				want = 1
			}
			if calls != want {
				t.Fatalf("conflict sent %d calls, want %d", calls, want)
			}
		})
	}
}

func TestStageCConcurrentReserveEntersOnce(t *testing.T) {
	c, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", 200, nil)
	ctx := fixedStageCContext()
	p, req := prepareReplayPlan(t, c, ctx)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return replayResponse(r, stageCReplayFixture(t)), nil
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, marked, err := c.ReserveSpendLeaseAdmission(ctx, p, req)
		if err != nil || !marked {
			t.Errorf("first reserve: marked=%v err=%v", marked, err)
		}
	}()
	<-entered
	second := make(chan error, 1)
	go func() { _, _, err := c.ReserveSpendLeaseAdmission(ctx, p, req); second <- err }()
	var err error
	select {
	case err = <-second:
	case <-time.After(time.Second):
		t.Error("second reserve reached the blocked transport")
	}
	close(release)
	wg.Wait()
	requireReplayError(t, err, 409, "idempotency_replay", "idempotency_replay")
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestStageCReplayAcceptanceMatrix(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(map[string]any)
		status int
	}{
		{"marked_different_nonce", func(d map[string]any) { d["invocation_nonce"] = "old" }, 0},
		{"unmarked_absent_nonce", func(d map[string]any) { delete(d, "spend_lease_admission"); delete(d, "invocation_nonce") }, 409},
		{"unmarked_different_nonce", func(d map[string]any) { delete(d, "spend_lease_admission"); d["invocation_nonce"] = "other" }, 409},
		{"unmarked_matching_nonce", func(d map[string]any) {
			delete(d, "spend_lease_admission")
			d["invocation_nonce"] = "00112233445566778899aabbccddeeff"
		}, 0},
		{"unmarked_fresh", func(d map[string]any) { delete(d, "spend_lease_admission"); d["idempotent_replay"] = false }, 0},
		{"null_marker", func(d map[string]any) { d["spend_lease_admission"] = nil }, 502},
		{"scalar_marker", func(d map[string]any) { d["spend_lease_admission"] = true }, 502},
		{"bad_member_type", func(d map[string]any) { d["spend_lease_admission"].(map[string]any)["accepted"] = "true" }, 502},
		{"false_marker_matching_nonce", func(d map[string]any) {
			d["spend_lease_admission"].(map[string]any)["accepted"] = false
			d["invocation_nonce"] = "00112233445566778899aabbccddeeff"
		}, 502},
		{"missing_hash", func(d map[string]any) { delete(d["spend_lease_admission"].(map[string]any), "receipt_hash") }, 502},
		{"wrong_hash", func(d map[string]any) { d["spend_lease_admission"].(map[string]any)["receipt_hash"] = "wrong" }, 502},
		{"missing_authorization", func(d map[string]any) { delete(d, "authorization_id") }, 502},
		{"missing_remaining", func(d map[string]any) { delete(d["spend_lease"].(map[string]any), "remaining_micro") }, 502},
		{"negative_remaining", func(d map[string]any) { d["spend_lease"].(map[string]any)["remaining_micro"] = -1 }, 502},
		{"over_cap_remaining", func(d map[string]any) { d["spend_lease"].(map[string]any)["remaining_micro"] = 1000001 }, 502},
		{"workspace", func(d map[string]any) { d["workspace_id"] = "other" }, 502},
		{"key", func(d map[string]any) { d["api_key_hash"] = "other" }, 502},
		{"route", func(d map[string]any) { d["upstream_model"] = "other" }, 502},
		{"candidate", func(d map[string]any) { d["route_candidates"].([]any)[0].(map[string]any)["upstream_model"] = "other" }, 502},
		{"region", func(d map[string]any) { d["region"] = "other" }, 502},
		{"billing", func(d map[string]any) { d["receipt_fee_basis_points"] = 1 }, 502},
		{"alias", func(d map[string]any) { d["response_model"] = "other" }, 502},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var wire map[string]any
			if err := json.Unmarshal(stageCReplayFixture(t), &wire); err != nil {
				t.Fatal(err)
			}
			d := wire["data"].(map[string]any)
			tc.edit(d)
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			c, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", 200, nil)
			c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return replayResponse(r, raw), nil })
			ctx := fixedStageCContext()
			p, req := prepareReplayPlan(t, c, ctx)
			a, marked, err := c.ReserveSpendLeaseAdmission(ctx, p, req)
			if tc.status == 0 {
				if err != nil || a == nil || marked != (d["spend_lease_admission"] != nil) {
					t.Fatalf("auth=%v marked=%v err=%v", a, marked, err)
				}
				return
			}
			if a != nil || marked {
				t.Fatal("invalid response opened reserve gate")
			}
			kind, reason := "admission_rejected", "receipt_invalid"
			if tc.status == 409 {
				kind = "idempotency_replay"
				reason = kind
			}
			requireReplayError(t, err, tc.status, kind, reason)
			if _, claimed := p.owner.claimed[p.key]; claimed {
				t.Fatal("invalid response consumed acceptance claim")
			}
		})
	}
}

func TestChatOrdinaryAuthorizeReplayUnchanged(t *testing.T) {
	for _, nonce := range []string{"absent", "different", "matching"} {
		t.Run(nonce, func(t *testing.T) {
			c, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", 200, nil)
			c.ConfigureSpendLeaseLocalAdmission(false)
			ctx := fixedStageCContext()
			calls := 0
			c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var b map[string]any
				if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
					t.Fatal(err)
				}
				if b["invocation_nonce"] != "00112233445566778899aabbccddeeff" || b["spend_lease_admission"] != nil {
					t.Fatalf("ordinary request changed: %v", b)
				}
				var wire map[string]any
				_ = json.Unmarshal(stageCReplayFixture(t), &wire)
				d := wire["data"].(map[string]any)
				// A receipt marker on an ordinary/rollback request grants no exemption.
				delete(d, "invocation_nonce")
				if nonce == "matching" {
					d["invocation_nonce"] = b["invocation_nonce"]
				}
				if nonce == "different" {
					d["invocation_nonce"] = "old"
				}
				raw, _ := json.Marshal(wire)
				return replayResponse(r, raw), nil
			})
			req := stageCFixtureRequest()
			a, err := c.AuthorizeWithRoute(ctx, "sk-stage-c-fixture", req, "chat.completions")
			if nonce == "matching" {
				if err != nil || a == nil {
					t.Fatalf("ordinary matching replay: %v", err)
				}
				_, err = c.AuthorizeWithRoute(ctx, "sk-stage-c-fixture", req, "chat.completions")
			}
			requireReplayError(t, err, 409, "idempotency_replay", "idempotency_replay")
			want := 1
			if nonce == "matching" {
				want = 2
			}
			if calls != want {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestStageCReplayOnlyReducesCapacity(t *testing.T) {
	for _, remaining := range []int64{100000, 1000000} {
		t.Run(fmt.Sprint(remaining), func(t *testing.T) {
			c, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", 200, nil)
			c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var wire map[string]any
				_ = json.Unmarshal(stageCReplayFixture(t), &wire)
				wire["data"].(map[string]any)["spend_lease"].(map[string]any)["remaining_micro"] = remaining
				raw, _ := json.Marshal(wire)
				return replayResponse(r, raw), nil
			})
			ctx := fixedStageCContext()
			p, req := prepareReplayPlan(t, c, ctx)
			_, marked, err := c.ReserveSpendLeaseAdmission(ctx, p, req)
			if err != nil || !marked {
				t.Fatalf("marked=%v err=%v", marked, err)
			}
			req.IdempotencyKey = "next-capacity-probe"
			next, err := c.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_006_000))
			if err != nil || next == nil {
				t.Fatalf("next=%v err=%v", next, err)
			}
			defer next.Cancel()
			want := min(p.admission.RemainingAfterMicro, remaining) - next.admission.EstimateMicro
			if next.admission.RemainingAfterMicro != want {
				t.Fatalf("remaining=%d want=%d", next.admission.RemainingAfterMicro, want)
			}
		})
	}
}
