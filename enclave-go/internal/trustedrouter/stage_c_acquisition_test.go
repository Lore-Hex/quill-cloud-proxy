package trustedrouter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

// No state seeding: every case obtains its signed grant through AuthorizeWithRoute,
// including deliberately over-advertised grants to test the enclave's own guard.
func TestStageCColdGrantTierCapabilityReplayMatrix(t *testing.T) {
	for _, route := range []string{"chat.completions", "responses"} {
		for _, tier := range []string{"", "default", " \t\n", " default ", "DEFAULT", " DeFaUlT ", strings.Repeat(" ", 21) + "default", "priority", "auto", " PrIoRiTy ", " AUTO ", "flex", "scale", "standard", "unknown"} {
			for _, capability := range []bool{false, true} {
				for _, stream := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/tier=%q/capability=%t/stream=%t", route, tier, capability, stream), func(t *testing.T) {
						req := stageCFixtureRequest()
						req.ServiceTier, req.Stream = tier, stream
						grantRequest := *req
						grantRequest.ServiceTier = strings.ToLower(strings.TrimSpace(tier))
						c, signer, claims := stageCAdmissionClientForRequest(t, "admission_accepted_response.json", 200, nil, route, &grantRequest, func(c *spendlease.Claims) { c.LocalAdmissionAllowed = capability })
						observed := &observedStageCSigner{Signer: signer}
						c.spendLease.signer = observed
						before := stageCCapacity(t, c)
						ctx := fixedStageCContext()
						p, err := c.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", req, route, time.UnixMilli(2_000_000_005_000))
						eligible := capability && stream && (tier == "" || tier == "default")
						if err != nil || (p != nil) != eligible {
							t.Fatalf("eligible=%t plan=%v err=%v", eligible, p, err)
						}
						if !eligible {
							if stageCCapacity(t, c) != before || observed.messages.Load() != 0 || observed.digests.Load() != 0 {
								t.Fatal("local miss spent capacity or signed")
							}
							return // nil plan cannot authorize speculative dispatch; handler matrix checks actual order.
						}
						after := stageCCapacity(t, c)
						if after != before-p.admission.EstimateMicro || observed.messages.Load() != 1 {
							t.Fatal("preparation must decrement and sign exactly once")
						}
						if p.Local.APIKeyHash != claims.KeyHash || p.lookupHash != stageCFixtureLookupHash || p.admission.Lease.Claims.KeyHash != claims.KeyHash {
							t.Fatal("identity substitution")
						}
						parts, err := receipt.ParseJWS([]byte(p.admission.Receipt))
						if err != nil {
							t.Fatal(err)
						}
						var signed spendlease.AdmissionReceiptClaims
						if err := json.Unmarshal(parts.PayloadJSON, &signed); err != nil {
							t.Fatal(err)
						}
						if signed.KeyHash != claims.KeyHash {
							t.Fatal("receipt lost stored identity")
						}
						calls, holds := 0, 0
						var original []byte
						var proof string
						c.authorizeRetry = retryPolicy{attempts: 2}
						c.httpc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
							raw, _ := io.ReadAll(r.Body)
							calls++
							if stageCCapacity(t, c) != after || observed.messages.Load() != 1 || observed.digests.Load() != 1 {
								t.Fatal("retry spent capacity or re-signed")
							}
							if calls == 1 {
								var body map[string]any
								if err := json.Unmarshal(raw, &body); err != nil {
									t.Fatal(err)
								}
								if body["api_key_lookup_hash"] != stageCFixtureLookupHash || body["api_key_hash"] != nil || body["stream"] != true || body["invocation_nonce"] != nil {
									t.Fatalf("wrong reserve identities/stream: %s", raw)
								}
								if tier != "" && body["service_tier"] != tier {
									t.Fatal("wire changed supplied tier")
								}
								holds++
								original, proof = raw, r.Header.Get(spendlease.BootAuthHeader)
								return nil, io.ErrUnexpectedEOF
							}
							if !bytes.Equal(raw, original) || proof == "" || proof != r.Header.Get(spendlease.BootAuthHeader) {
								t.Fatal("lost-ack retry changed bytes/proof")
							}
							var replay map[string]any
							if err := json.Unmarshal(stageCReplayFixture(t), &replay); err != nil {
								t.Fatal(err)
							}
							replay["data"].(map[string]any)["spend_lease_admission"].(map[string]any)["receipt_hash"] = p.ReceiptHash()
							b, err := json.Marshal(replay)
							if err != nil {
								t.Fatal(err)
							}
							return replayResponse(r, b), nil
						})
						a, marked, err := c.ReserveSpendLeaseAdmission(ctx, p, req)
						if err != nil || !marked || a == nil || !a.IdempotentReplay || a.APIKeyHash != claims.KeyHash || a.AuthorizationID != "gwa-stage-c-fixture" || !admissionAuthorizationMatches(p.frozen, a) {
							t.Fatalf("reserve: auth=%v marked=%t err=%v", a, marked, err)
						}
						if calls != 2 || holds != 1 || stageCCapacity(t, c) != after || len(p.owner.claimed) != 1 {
							t.Fatal("expected one hold, decrement and claim")
						}
						_, _, err = c.ReserveSpendLeaseAdmission(ctx, p, req)
						requireReplayError(t, err, 409, "idempotency_replay", "idempotency_replay")
					})
				}
			}
		}
	}
}

func TestStageCOrdinaryGrantBindingFailuresRemainAdvisory(t *testing.T) {
	for _, name := range []string{"returned_stored", "missing_stored", "signed_stored", "workspace", "missing_workspace", "boot", "lookup"} {
		t.Run(name, func(t *testing.T) {
			c, signer, _ := stageCAdmissionClientForRequest(t, "admission_accepted_response.json", 200, nil, "chat.completions", stageCFixtureRequest(), func(c *spendlease.Claims) {
				if name == "signed_stored" {
					c.KeyHash = strings.Repeat("c", 64)
				}
				if name == "boot" {
					c.BootKID = "different-boot"
				}
			}, func(d map[string]any) {
				switch name {
				case "returned_stored":
					d["api_key_hash"] = "unrelated-stored-key"
				case "missing_stored":
					delete(d, "api_key_hash")
				case "signed_stored":
					d["api_key_hash"] = strings.Repeat("a", 64)
				case "workspace":
					d["workspace_id"] = "unrelated-workspace"
				case "missing_workspace":
					delete(d, "workspace_id")
				}
			})
			observed := &observedStageCSigner{Signer: signer}
			c.spendLease.signer = observed
			ctx := fixedStageCContext()
			if name == "lookup" {
				var err error
				ctx, err = WithAPIKeyLookupHash(ctx, strings.Repeat("d", 64))
				if err != nil {
					t.Fatal(err)
				}
			}
			p, err := c.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", stageCFixtureRequest(), "chat.completions", time.UnixMilli(2_000_000_005_000))
			if err != nil || p != nil || observed.messages.Load() != 0 {
				t.Fatalf("invalid binding prepared: %v %v", p, err)
			}
		})
	}
}
