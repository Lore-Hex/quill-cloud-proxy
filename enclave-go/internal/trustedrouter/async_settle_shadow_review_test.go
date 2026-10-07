package trustedrouter

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Reproduce the reviewer's real canonical-size snapshots without padded JSON or
// an artificial size argument. Re-sign the changed hash with the fixture seed.
func shadowBoundaryAuthorization(t *testing.T, size int) (*Client, *Authorization) {
	t.Helper()
	c, a := shadowAuth(t)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(a.BillingSnapshot, &fields); err != nil {
		t.Fatal(err)
	}
	candidates := a.shadowSettlement.snapshot.Candidates()
	candidate := &candidates[0]
	candidate.Tiers = nil
	canonical := func() []byte {
		fields["candidates"], _ = json.Marshal(candidates)
		raw, err := canonicalShadow(fields)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for bound := int64(999999999999999); ; bound++ {
		limit := bound
		candidate.Tiers = append(candidate.Tiers, billingv1.Tier{MaxPromptTokens: &limit, Rates: candidate.Rates})
		if len(canonical()) > size {
			candidate.Tiers = candidate.Tiers[:len(candidate.Tiers)-1]
			break
		}
	}
	remaining := size - len(canonical())
	padding := min(remaining, 128-len(candidate.ModelID))
	candidate.ModelID += strings.Repeat("a", padding)
	remaining -= padding
	for i := range candidate.Tiers {
		for n := min(remaining, 12); n > 0; n-- {
			candidate.Tiers[i].Rates.InputMicroPerMillion = candidate.Tiers[i].Rates.InputMicroPerMillion*10 + 1
			remaining--
		}
	}
	raw := canonical()
	snapshot, err := billingv1.ParseSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = billingv1.CanonicalBytes(snapshot)
	if err != nil || len(raw) != size {
		t.Fatalf("canonical snapshot size %d, want %d: %v", len(raw), size, err)
	}
	hash, err := billingv1.CanonicalHash(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(a.BillingShadowBinding), ".")
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	claims["snapshot_hash"] = hash
	claimsJSON, err = canonicalShadow(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	a.BillingShadowBinding = BillingSnapshotDigest(signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signed))))
	a.BillingSnapshot, a.BillingSnapshotHash, a.shadowSettlement = raw, BillingSnapshotDigest(hash), nil
	c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.shadowSettlement == nil {
		t.Fatal("valid boundary authorization refused")
	}
	return c, a
}

func TestReviewFailureKeepsMode(t *testing.T) {
	setShadowRevision(t)
	c, a := shadowBoundaryAuthorization(t, 6144)
	u := shadowUsage()
	header := c.withShadowHeader(t.Context(), a, u, "settle").Value(shadowHeaderKey{}).(string)
	if wire := decodeShadow(t, header); wire["billing_snapshot"] != nil || string(wire["go_error"]) != "null" {
		t.Fatal("precondition: successful 6144-byte snapshot must overflow full")
	}
	u.ShadowObservation.Present = false
	header = c.withShadowHeader(t.Context(), a, u, "settle").Value(shadowHeaderKey{}).(string)
	wire := decodeShadow(t, header)
	if wire["billing_snapshot"] != nil || string(wire["go_error"]) != `"usage_missing"` {
		t.Fatal("failure reinstated snapshot after success selected hash-only")
	}
}

func TestShadowCanonicalSnapshotBoundaries(t *testing.T) {
	setShadowRevision(t)
	for _, size := range []int{5200, 6144, 6145} {
		for _, kind := range []string{"settle", "refund"} {
			for _, failureFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/failure-first=%v", size, kind, failureFirst), func(t *testing.T) {
					c, a := shadowBoundaryAuthorization(t, size)
					before := *a.shadowSettlement
					wantFull := size == 5200
					for _, missing := range []bool{failureFirst, !failureFirst} {
						u := shadowUsage()
						u.ShadowObservation.Present = !missing
						first := c.withShadowHeader(t.Context(), a, u, kind).Value(shadowHeaderKey{})
						if first == nil {
							t.Fatal("missing bounded header")
						}
						wire := decodeShadow(t, first.(string))
						if (wire["billing_snapshot"] != nil) != wantFull || string(wire["go_error"]) != map[bool]string{false: "null", true: `"usage_missing"`}[missing] {
							t.Fatal("wrong transport mode or failure variant")
						}
						if wantFull && !bytes.Equal(wire["billing_snapshot"], a.shadowSettlement.raw) {
							t.Fatal("snapshot changed")
						}
						if again := c.withShadowHeader(t.Context(), a, u, kind).Value(shadowHeaderKey{}); again != first {
							t.Fatal("boundary retry changed")
						}
					}
					if before.full != a.shadowSettlement.full || !bytes.Equal(before.raw, a.shadowSettlement.raw) {
						t.Fatal("authorization mode or snapshot changed")
					}
				})
			}
		}
	}
}

func TestReviewHTTPRetryInterleaving(t *testing.T) {
	setShadowRevision(t)
	c, a := shadowAuth(t)
	var bodies, headers []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		headers = append(headers, r.Header.Get(shadowSettlementHeader))
		if r.URL.Path != "/internal/gateway/settle" || r.Header.Get(asyncSettlementHeader) != "" || len(r.Header.Values(shadowSettlementHeader)) != 1 {
			t.Error("legacy settle path or header separation changed")
		}
		_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":2}}`)
	}))
	defer server.Close()
	c.baseURLs, c.httpc = []string{server.URL}, server.Client()
	a.pinControlPlaneEndpoint(0)
	u := shadowUsage()
	u.ShadowObservation.AvailableAt = time.Now().Add(-time.Second)
	if _, err := c.Settle(t.Context(), a, u); err != nil {
		t.Fatal(err)
	}
	copyAuthorization := *a
	v := u
	v.OutputTokens++
	if _, err := c.Settle(t.Context(), &copyAuthorization, v); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Settle(t.Context(), a, u); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 || bodies[0] != bodies[2] || bodies[0] == bodies[1] {
		t.Fatal("invalid repro: legacy A bodies must match and B must differ")
	}
	if headers[0] == "" || headers[0] != headers[2] {
		t.Fatal("identical legacy A bodies have different frozen header after B using copied authorization")
	}
	var terminal billingv1.TerminalEnvelope
	if json.Unmarshal(decodeShadow(t, headers[1])["terminal"], &terminal) != nil || terminal.Usage.OutputTokens != 2 {
		t.Fatal("B reused A's terminal")
	}
}

func TestShadowRetryIdentityAndCapacity(t *testing.T) {
	setShadowRevision(t)
	c, a := shadowAuth(t)
	u := shadowUsage()
	// A copied Usage shares retry storage, so the full identity must distinguish
	// changed usage, authorization and kind even under concurrent sends.
	var headers [8]any
	var wait sync.WaitGroup
	for i := range headers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			v := u
			v.OutputTokens += i
			headers[i] = c.withShadowHeader(t.Context(), a, v, "settle").Value(shadowHeaderKey{})
		}()
	}
	wait.Wait()
	for i, header := range headers {
		v := u
		v.OutputTokens += i
		if header == nil || header != c.withShadowHeader(t.Context(), a, v, "settle").Value(shadowHeaderKey{}) {
			t.Fatal("concurrent retry lost frozen bytes")
		}
	}
	refund := c.withShadowHeader(t.Context(), a, u, "refund").Value(shadowHeaderKey{}).(string)
	var terminal billingv1.TerminalEnvelope
	if json.Unmarshal(decodeShadow(t, refund)["terminal"], &terminal) != nil || terminal.TerminalKind != "refund" || terminal.ChargeMicro != 0 {
		t.Fatal("kind missing from retry identity")
	}
	_, other := shadowAuth(t)
	_ = c.withShadowHeader(t.Context(), other, u, "settle")
	if len(u.ShadowObservation.retries.frozen) != len(headers)+2 {
		t.Fatal("authorization missing from retry identity")
	}
	for i := 0; i < shadowRetryEntries; i++ {
		v := u
		v.OutputTokens += 100 + i
		_ = c.withShadowHeader(t.Context(), a, v, "settle")
	}
	if len(u.ShadowObservation.retries.frozen) != shadowRetryEntries || headers[0] != c.withShadowHeader(t.Context(), a, u, "settle").Value(shadowHeaderKey{}) {
		t.Fatal("capacity must preserve existing retries without growing storage")
	}
}

func TestReviewRetainAllCandidates(t *testing.T) {
	var cases []struct {
		Snapshot   json.RawMessage            `json:"snapshot"`
		Envelope   map[string]json.RawMessage `json:"envelope"`
		Candidates int                        `json:"candidates"`
	}
	json.Unmarshal(asyncFixture(t, "shadow_transport_v1"), &cases)
	for _, tc := range cases {
		if tc.Candidates != 43 {
			continue
		}
		c, a := shadowAuth(t)
		a.shadowSettlement = nil
		a.BillingSnapshot = tc.Snapshot
		json.Unmarshal(tc.Envelope["billing_shadow_binding"], &a.BillingShadowBinding)
		claims, ok := shadowClaims(string(a.BillingShadowBinding))
		if !ok {
			t.Fatal("claims")
		}
		a.BillingSnapshotHash = BillingSnapshotDigest(claims.SnapshotHash)
		c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
		if a.shadowSettlement == nil {
			t.Fatal("retain")
		}
		sh := a.shadowSettlement
		if len(sh.snapshot.Candidates()) != 43 {
			t.Fatal("candidate list trimmed")
		}
		u := shadowUsage()
		u.SelectedEndpoint = sh.snapshot.Candidates()[42].EndpointID
		body := buildShadowEnvelope(sh, u, "settle", shadowFixtureRevision)
		if body["terminal"] == nil {
			t.Fatal(body)
		}
		h, e := encodeShadow(body, sh.full)
		if e != nil {
			t.Fatal(e)
		}
		if _, full := decodeShadow(t, h)["billing_snapshot"]; full {
			t.Fatal("hash-only expected")
		}
	}
}
