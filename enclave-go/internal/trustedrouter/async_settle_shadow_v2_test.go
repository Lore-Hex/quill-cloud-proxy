package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var shadowV2Pins = map[string]string{
	"authorize_compared.json":          "f405ada111b96a50f9f548f2dee415f609bf81cd914de182cdf7f11e14574e94",
	"authorize_excluded.json":          "70392c30c884c9c6231fc72d7a28d3971e018295276c79d9d83c003f827a0045",
	"capability_headers.json":          "b8321f95f86c6fa29b92e8c7286bdf69b0a505b5fac02b437f172f02aff094d2",
	"certificate_record.json":          "afa80d6fa9b9c4c2585b43888ef2338fbada2e561bbe863b0d10cbcf1873b6cd",
	"closure.json":                     "ee4c8fb9561a3426480323c9566f05c55b9b2c32e8b5f81a615dca0bec5c8cef",
	"controls.json":                    "b3bb22472249c94283166a737965aa768b8d2f906ae36255a6bc5bf6e517d2ed",
	"counter.json":                     "f204afbde105b0c35178e3623196199f7e5a02d84d589bf4acfad1da1886a1e0",
	"exclusion_certificate.json":       "1ac66af1d68255374f41f234463bbede61f294dbe53cacd0fb284d8e8478cb64",
	"gate_outputs.json":                "1a3638ebadba0a8113495baa039c73e421eb888414b49be1535c7322f1f9d572",
	"health.json":                      "f25b97e759c96806849e9d81efc4fe881d793fa22ea188ff10aec7c76c3a64bb",
	"health_claim.json":                "7a692317460d7f3e72d751ea1db4c479515438b676a4fb891be503553aee88cf",
	"manifest.json":                    "dc364e152a770b2904c41f13b3af54625da4fcb7652571129e7481e195b1d9e7",
	"prerequisite_ledger.json":         "123f1102be7c33024f3388b8e2730da55a6afc9ae84a73972d0183a4b6085292",
	"proof_manifest.json":              "f8cd2b2a6c283e4d97578832dc96a55eb794bafcb22c335e634a134ddffed492",
	"purpose_rejections.json":          "15b745b177744fedcaed659ac41abbf05aad7b9fc75705d85bb6f81cd7ac86b7",
	"receipt_pages.json":               "e9f83ebb045d22c3d127bd52ecebefe919ea994ef7af21d885e28a934842e84d",
	"sample.json":                      "b3af8a27de86863035f84ec790945a6d2efcbbcfc56dfff95917e2d7fffda759",
	"terminal_compared_failure.json":   "a33e7f30d6501bfae2ebb08bdc713e459e7bc0ebb2d553fd3933c3f85a158043",
	"terminal_compared_full.json":      "d5e6fcfd096da7eb7820af10f38983f6d7661cce94abef902acaff9f3e64488c",
	"terminal_compared_hash_only.json": "7c41c282cae00eee2919f13322c35c7a073dc6240a35a4ffcf423ecf16da7fae",
	"terminal_excluded_refund.json":    "3694f06b9b72e9e45dadc70148df372fe3c8067c35f7e1fe3ff78fbd1e7e2554",
	"terminal_excluded_settle.json":    "698789fb3742739eab40eaf117a10b85cf66cb946144323887a035fb4e4fa491",
	"wire_rejections.json":             "fac4e0550164aaa315344bb6f4e66ef2509ee13e037463098a0526ee74db6771",
}

func shadowV2Variants(t *testing.T, name string) []map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "async_settlement", "shadow_v2", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Variants []map[string]json.RawMessage `json:"variants"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Variants
}
func v2String(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func v2Object(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func v2Authorization(t *testing.T, v map[string]json.RawMessage) *Authorization {
	t.Helper()
	a := fixtureAuthorization(t, true)
	if err := json.Unmarshal(v["object"], a); err != nil {
		t.Fatal(err)
	}
	captureShadowProjection(a, v["object"])
	return a
}
func TestShadowV2FixturePins(t *testing.T) {
	root := filepath.Join("testdata", "async_settlement", "shadow_v2")
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 23 {
		t.Fatal("fixture inventory")
	}
	for name, want := range shadowV2Pins {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != want {
			t.Fatal(name)
		}
	}
	var manifest struct {
		Files map[string]struct {
			SHA      string   `json:"sha256"`
			Variants []string `json:"variants"`
		} `json:"files"`
		Legacy map[string]string `json:"legacy_files"`
	}
	raw, _ := os.ReadFile(filepath.Join(root, "manifest.json"))
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("manifest")
	}
	if len(manifest.Files) != 22 {
		t.Fatal("manifest inventory")
	}
	for name, entry := range manifest.Files {
		if shadowV2Pins[name] != entry.SHA {
			t.Fatal(name)
		}
		vs := shadowV2Variants(t, strings.TrimSuffix(name, ".json"))
		var names []string
		for _, v := range vs {
			names = append(names, v2String(t, v["name"]))
		}
		if !reflect.DeepEqual(names, entry.Variants) {
			t.Fatal(name)
		}
	}
	missing := map[string]bool{"enclave_keyring_v1.json": true, "error_envelopes_v1.json": true, "snapshot_sync_refund_v1.json": true}
	found := 0
	for name, want := range manifest.Legacy {
		raw, err := os.ReadFile(filepath.Join("testdata", "async_settlement", name))
		if os.IsNotExist(err) && missing[name] {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != want {
			t.Fatal(name)
		}
		found++
	}
	if found != 19 {
		t.Fatal(found)
	}
}

func TestShadowV2CertificateVectors(t *testing.T) {
	for _, file := range []string{"exclusion_certificate", "wire_rejections"} {
		for _, v := range shadowV2Variants(t, file) {
			name := v2String(t, v["name"])
			t.Run(file+"/"+name, func(t *testing.T) {
				if raw, ok := v["locator"]; ok {
					var loc shadowReceiptLocator
					if json.Unmarshal(raw, &loc) != nil || !shadowLocatorValid(loc) {
						t.Fatal("maximum locator")
					}
					return
				}
				raw, ok := v["certificate"]
				if !ok {
					return
				}
				_, accepted := shadowCertificateClaims(v2String(t, raw))
				rejected := map[string]bool{"one-byte-over-claims-kid-1": true, "one-byte-over-claims-kid-64": true, "locator-missing-boot": true, "locator-extra": true, "locator-invalid-day": true, "signed-noncanonical-payload": true, "ticket-as-certificate": true, "binding-as-certificate": true, "signed-duplicate-payload": true, "signed-duplicate-header": true, "signed-noncanonical-header": true}
				if accepted == rejected[name] {
					t.Fatal("bounded local reading disagrees; not a signature/expiry/backing verdict")
				}
			})
		}
	}
}

func TestShadowV2TerminalFixtureBytes(t *testing.T) {
	for _, file := range []string{"terminal_excluded_settle", "terminal_excluded_refund", "terminal_compared_full", "terminal_compared_hash_only", "terminal_compared_failure"} {
		for _, v := range shadowV2Variants(t, file) {
			t.Run(file+"/"+v2String(t, v["name"]), func(t *testing.T) {
				if _, ok := v["canonical"]; !ok {
					var tier billingv1.Tier
					if json.Unmarshal(v["object"], &tier) != nil {
						t.Fatal("tier fixture")
					}
					raw, err := billingv1.CanonicalBytes(tier)
					want, canonicalErr := canonicalShadow(v2Object(t, v["object"]))
					if err != nil || canonicalErr != nil || !bytes.Equal(raw, want) {
						t.Fatal("nested tier bytes")
					}
					return
				}
				var obj map[string]any
				decoder := json.NewDecoder(bytes.NewReader(v["object"]))
				decoder.UseNumber()
				if decoder.Decode(&obj) != nil {
					t.Fatal("object")
				}
				header, err := encodeShadow(obj, obj["billing_snapshot"] != nil)
				if err != nil {
					t.Fatal(err)
				}
				if header != v2String(t, v["header"]) {
					t.Fatal("fixture header bytes differ")
				}
				raw, _ := base64.RawURLEncoding.DecodeString(header)
				if string(raw) != v2String(t, v["canonical"]) {
					t.Fatal("canonical bytes differ")
				}
			})
		}
	}
}

type shadowV2Transport func(*http.Request) (*http.Response, error)

func (f shadowV2Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func v2Reply(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestShadowV2SendEchoAndMoney(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	old := ShadowBuildRevision
	t.Cleanup(func() { ShadowBuildRevision = old })
	for _, kind := range []string{"settle", "refund", "refund-detailed", "refund-attributed"} {
		for _, excluded := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/%v", kind, excluded), func(t *testing.T) {
				file := "authorize_compared"
				terminalFile := "terminal_compared_full"
				if excluded {
					file = "authorize_excluded"
					terminalFile = "terminal_excluded_settle"
					if kind != "settle" {
						terminalFile = "terminal_excluded_refund"
					}
				}
				v := shadowV2Variants(t, file)[0]
				a := v2Authorization(t, v)
				a.Provider = "openai"
				expected := shadowV2Variants(t, terminalFile)[0]
				obj := v2Object(t, expected["object"])
				ShadowBuildRevision = v2String(t, obj["go_revision"])
				response, _ := json.Marshal(map[string]any{"data": v2WireAuthorization(a)})
				var bodies []string
				var headers []string
				var markers []string
				transport := shadowV2Transport(func(r *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(r.Body)
					if r.URL.Path == "/internal/gateway/authorize" {
						markers = append(markers, r.Header.Get(shadowPolicyHeader))
						return v2Reply(string(response)), nil
					}
					if r.Header.Get(asyncSettlementHeader) != "" || r.Header.Get(shadowPolicyHeader) != "" {
						t.Error("terminal mode/capability")
					}
					bodies = append(bodies, string(raw))
					headers = append(headers, r.Header.Get(shadowSettlementHeader))
					return v2Reply(`{"data":{"settled":true,"cost_microdollars":2}}`), nil
				})
				client := New("https://trustedrouter.com", "test", &http.Client{Transport: transport})
				auth, err := client.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{Model: "fixture"}, "chat.completions")
				if err != nil {
					t.Fatal(err)
				}
				if auth.async != nil || client.AsyncSettlementNegotiated(auth) {
					t.Fatal("v2 bound async")
				}
				u := fixtureUsage()
				u.InputTokens, u.OutputTokens = 1, 1
				u.ShadowObservation = ObserveShadowUsage(true, "")
				u.ShadowObservation.AvailableAt = u.ShadowObservation.AvailableAt.Add(-1e6)
				send := func() {
					var err error
					switch kind {
					case "settle":
						_, err = client.Settle(t.Context(), auth, u)
					case "refund":
						err = client.Refund(t.Context(), auth, 502, "upstream_error", 1, nil)
					case "refund-detailed":
						_, err = client.RefundDetailed(t.Context(), auth, 502, "upstream_error", 1, nil)
					case "refund-attributed":
						_, err = client.RefundDetailedAttributed(t.Context(), auth, 502, "upstream_error", 1, nil, RefundAttribution{})
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if kind == "settle" {
					auth.RecordShadowInvocation(u.SelectedEndpoint, "openai")
				}
				send()
				send()
				client.asyncShadow = false
				send()
				if len(markers) != 1 || markers[0] != shadowPolicyV2 || len(headers) != 3 || headers[0] == "" || headers[0] != headers[1] || headers[2] != "" {
					t.Fatal("marker or retry bytes")
				}
				if bodies[0] != bodies[1] || bodies[0] != bodies[2] {
					t.Fatal("legacy body changed")
				}
				if excluded && headers[0] != v2String(t, expected["header"]) {
					t.Fatal("real send differs from fixture")
				}
			})
		}
	}
}

func TestShadowV2RetentionOrderGateAndIsolation(t *testing.T) {
	old := parseShadowSnapshot
	t.Cleanup(func() { parseShadowSnapshot = old })
	calls := 0
	parseShadowSnapshot = func(raw []byte) (billingv1.Snapshot, error) { calls++; panic("snapshot spy") }
	for _, route := range []string{"chat.completions", "responses", "messages", "embeddings", "images", "videos", "decide", "audio.speech"} {
		for _, enabled := range []bool{false, true} {
			for _, policy := range []string{"absent", "valid", "malformed", "wrong"} {
				t.Run(fmt.Sprintf("%s/%v/%s", route, enabled, policy), func(t *testing.T) {
					a := v2Authorization(t, shadowV2Variants(t, "authorize_excluded")[0])
					req := &qtypes.OpenAIChatRequest{}
					// Request-level fixture's immutable route is deliberately not rewritten.
					switch policy {
					case "absent":
						a.BillingShadowPolicy = nil
					case "malformed":
						a.BillingShadowPolicy = json.RawMessage(`123`)
					case "wrong":
						a.BillingShadowPolicy = json.RawMessage(`"other"`)
					}
					a.BillingSnapshot = json.RawMessage(strings.Repeat("!", 70000))
					c := fixtureClient()
					c.asyncShadow = enabled
					before := calls
					c.retainShadowAuthorization(a, req, route)
					if calls != before {
						t.Fatal("snapshot parsed before exclusion retention")
					}
					want := enabled && policy == "valid" && route == "chat.completions"
					if (a.shadowSettlement != nil) != want {
						t.Fatal("policy or identity gate")
					}
					if want && (len(a.shadowSettlement.raw) != 0 || a.shadowSettlement.proof != "") {
						t.Fatal("exclusion retained pricing")
					}
				})
			}
		}
	}
	// Compared panic is diagnostic only, and cannot poison the legacy authorize.
	a := v2Authorization(t, shadowV2Variants(t, "authorize_compared")[0])
	c := fixtureClient()
	c.asyncShadow = true
	c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.shadowSettlement != nil || calls != 1 {
		t.Fatal("panic isolation")
	}
	setShadowRevision(t)
	savedBuilder := buildShadowTerminal
	t.Cleanup(func() { buildShadowTerminal = savedBuilder })
	buildShadowTerminal = func(*shadowAuthorization, Usage, string, string) map[string]any { panic("builder spy") }
	a.shadowSettlement = &shadowAuthorization{v2: true}
	ctx := c.withShadowHeader(t.Context(), a, Usage{ShadowObservation: ObserveShadowUsage(true, "")}, "settle")
	if h, _ := ctx.Value(shadowHeaderKey{}).(string); h != "" {
		t.Fatal("panic diagnostic escaped")
	}
}

func TestShadowV2Bounds(t *testing.T) {
	for _, n := range []int{6144, 6145} {
		if shadowFullFits(map[string]any{}, n) != (n == 6144) {
			t.Fatal("inline boundary")
		}
	}
	for _, excluded := range []bool{false, true} {
		limit := 8192
		if excluded {
			limit = 4096
		}
		for _, n := range []int{limit, limit + 1} {
			if shadowWireFits(make([]byte, n), excluded) != (n == limit) {
				t.Fatal("decoded/encoded boundary", excluded, n)
			}
		}
	}
	// The encoded limits are conjunctive: 4096 -> 5462, 4097 -> 5463;
	// the retained 8192 cap dominates the older 12288 encoded cap.
	if base64.RawURLEncoding.EncodedLen(4096) != 5462 || base64.RawURLEncoding.EncodedLen(4097) != 5463 {
		t.Fatal("encoding arithmetic")
	}
	for _, v := range shadowV2Variants(t, "exclusion_certificate") {
		if strings.HasPrefix(v2String(t, v["name"]), "maximum-claims-") {
			proof := v2String(t, v["certificate"])
			if len(proof) != 2048 {
				t.Fatal("fixture limit")
			}
			if _, ok := shadowCertificateClaims(proof); !ok {
				t.Fatal("exact certificate limit")
			}
			if _, ok := shadowCertificateClaims(proof + "A"); ok {
				t.Fatal("over certificate limit")
			}
		}
	}
	for _, size := range []int{6144, 6145, 65536, 65537} {
		c, a := shadowV2SizedAuthorization(t, size, 8)
		a.shadowSettlement = nil
		a.BillingShadowPolicy = json.RawMessage(`"shadow-v2"`)
		c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
		if size > 65536 {
			if a.shadowSettlement != nil {
				t.Fatal("local cap")
			}
		} else if a.shadowSettlement == nil || (size > 6144 && a.shadowSettlement.full) {
			t.Fatal("inline/local cap", size)
		}
	}
}

func TestShadowV2PurposeAndNeverBind(t *testing.T) {
	matrix := shadowV2Variants(t, "purpose_rejections")[0]
	var cases []map[string]json.RawMessage
	if json.Unmarshal(matrix["cases"], &cases) != nil {
		t.Fatal("cases")
	}
	for _, v := range cases {
		t.Run(v2String(t, v["name"]), func(t *testing.T) {
			token := v2String(t, v["certificate"])
			target := v2String(t, v["target"])
			switch target {
			case "foreign_certificate":
				if _, ok := shadowCertificateClaims(token); ok {
					t.Fatal("foreign certificate")
				}
			case "foreign_binding":
				if _, ok := shadowClaims(token); ok {
					t.Fatal("foreign binding")
				}
			default:
				key := v2Object(t, v["key"])
				pub, err := base64.RawURLEncoding.DecodeString(v2String(t, key["public_key_b64url"]))
				if err != nil {
					t.Fatal(err)
				}
				kid := v2String(t, key["kid"])
				if _, err = receipt.VerifyCompactJWS(token, map[string]ed25519.PublicKey{kid: pub}, "tr-async-settle-v1"); err == nil {
					t.Fatal("foreign ticket")
				}
			}
		})
	}
	for _, file := range []string{"authorize_excluded", "authorize_compared"} {
		a := v2Authorization(t, shadowV2Variants(t, file)[0])
		c := fixtureClient()
		c.asyncShadow = true
		c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
		if a.async != nil {
			t.Fatal("shadow async binding")
		}
	}
	a := fixtureAuthorization(t, true)
	a.SettlementTicket = v2String(t, matrix["certificate"])
	c := fixtureClient()
	c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.async != nil {
		t.Fatal("certificate bound async")
	}
}

func TestShadowV2OldRouterOracle(t *testing.T) {
	setShadowRevision(t)
	c, a := shadowAuth(t)
	u := shadowUsage()
	u.ShadowObservation.AvailableAt = u.ShadowObservation.AvailableAt.Add(-1e6)
	baseline := c.withShadowHeader(context.Background(), a, u, "settle").Value(shadowHeaderKey{})
	a.BillingShadowExclusion = shadowV2Variants(t, "authorize_excluded")[0]["object"]
	a.shadowSettlement = nil
	c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	// No marker means the same v1 envelope (remove only nondeterministic timing).
	got := decodeShadow(t, c.withShadowHeader(context.Background(), a, u, "settle").Value(shadowHeaderKey{}).(string))
	want := decodeShadow(t, baseline.(string))
	delete(got, "handoff_prepare_us")
	delete(want, "handoff_prepare_us")
	if !reflect.DeepEqual(got, want) {
		t.Fatal("old router changed v1")
	}
}

// Synthetic size controls alter unsigned local-reading inputs in memory. No
// signing key, renewed proof or production acceptance is involved.
func shadowV2SizedAuthorization(t *testing.T, size, count int) (*Client, *Authorization) {
	t.Helper()
	c, a := shadowAuth(t)
	fields := v2Object(t, a.BillingSnapshot)
	original := a.shadowSettlement.snapshot.Candidates()[0]
	candidates := make([]billingv1.Candidate, count)
	for i := range candidates {
		candidates[i] = original
		candidates[i].EndpointID = fmt.Sprintf("endpoint-%03d", i)
		candidates[i].Tiers = []billingv1.Tier{}
	}
	raw := func() []byte {
		fields["candidates"], _ = json.Marshal(candidates)
		b, err := canonicalShadow(fields)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if size > 0 {
		for i := 0; i < count; i++ {
			for len(candidates[i].Tiers) < 64 {
				limit := int64(999999999999999 + len(candidates[i].Tiers))
				candidates[i].Tiers = append(candidates[i].Tiers, billingv1.Tier{MaxPromptTokens: &limit, Rates: original.Rates})
				if len(raw()) > size {
					candidates[i].Tiers = candidates[i].Tiers[:len(candidates[i].Tiers)-1]
					break
				}
			}
			if size-len(raw()) < 128 {
				break
			}
		}
		for i := range candidates {
			n := min(size-len(raw()), 128-len(candidates[i].ModelID))
			if n > 0 {
				candidates[i].ModelID += strings.Repeat("x", n)
			}
		}
		if len(raw()) != size {
			t.Fatalf("synthetic snapshot size %d, want %d", len(raw()), size)
		}
	}
	a.BillingSnapshot = raw()
	hash := fmt.Sprintf("%x", sha256.Sum256(a.BillingSnapshot))
	a.BillingSnapshotHash = BillingSnapshotDigest(hash)
	parts := strings.Split(string(a.BillingShadowBinding), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	claims := v2Object(t, payload)
	claims["snapshot_hash"], _ = json.Marshal(hash)
	payload, _ = canonicalShadow(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	a.BillingShadowBinding = BillingSnapshotDigest(strings.Join(parts, "."))
	a.shadowSettlement = nil
	return c, a
}

func TestShadowV2CandidateBound(t *testing.T) {
	for _, n := range []int{128, 129} {
		if shadowLocalFits(0, n) != (n == 128) {
			t.Fatal("shadow candidate bound")
		}
	}
	for _, count := range []int{64, 65, 128, 129} {
		c, a := shadowV2SizedAuthorization(t, 0, count)
		a.BillingShadowPolicy = json.RawMessage(`"shadow-v2"`)
		c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
		if (a.shadowSettlement != nil) != (count == 64) {
			t.Fatal("candidate bound", count)
		}
	}
}

func TestShadowV2WireRejectionShapes(t *testing.T) {
	for _, v := range shadowV2Variants(t, "wire_rejections") {
		if v2String(t, v["target"]) != "parse_terminal" {
			continue
		}
		t.Run(v2String(t, v["name"]), func(t *testing.T) {
			raw := []byte(v2String(t, v["raw"]))
			name := v2String(t, v["name"])
			if strings.HasPrefix(name, "excluded-") {
				if shadowWireFits(raw, true) != (v2String(t, v["expected"]) != "reject") {
					t.Fatal("wire bound")
				}
				return
			}
			// Terminal input is never parsed by the enclave. Show that the generated
			// exact object cannot produce these duplicate/version/key/type mutations.
			a := v2Authorization(t, shadowV2Variants(t, "authorize_excluded")[0])
			c := fixtureClient()
			c.asyncShadow = true
			c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			a.RecordShadowInvocation("openai/billing-v1@openai/prepaid", "openai")
			body, ok := buildShadowExcluded(a.shadowSettlement.exclusion, fixtureUsage(), "settle", strings.Repeat("a", 40))
			if !ok {
				t.Fatal("builder")
			}
			canonical, _ := canonicalShadow(body)
			if bytes.Equal(canonical, raw) {
				t.Fatal("built rejected shape")
			}
		})
	}
}

func TestShadowV2MarkerRoutesAndLegacyErrors(t *testing.T) {
	for _, route := range []string{"chat.completions", "responses", "messages", "embeddings", "images", "videos", "decide", "audio.speech"} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", route, enabled), func(t *testing.T) {
				flag := "off"
				if enabled {
					flag = "on"
				}
				t.Setenv("TR_ASYNC_SETTLE_SHADOW", flag)
				t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
				projection := shadowV2Variants(t, "authorize_excluded")[0]
				a := v2Authorization(t, projection)
				a.AdditionalCostReservationMicrodollars = 1
				response, _ := json.Marshal(map[string]any{"data": v2WireAuthorization(a)})
				calls := 0
				c := New("https://trustedrouter.com", "test", &http.Client{Transport: shadowV2Transport(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.Path == "/internal/gateway/authorize" {
						if (r.Header.Get(shadowPolicyHeader) == shadowPolicyV2) != enabled {
							t.Error("capability marker gate")
						}
						return v2Reply(string(response)), nil
					}
					if r.Header.Get(asyncSettlementHeader) != "" || r.Header.Get(shadowPolicyHeader) != "" {
						t.Error("terminal mode/capability")
					}
					if (!enabled || route != "chat.completions") && r.Header.Get(shadowSettlementHeader) != "" {
						t.Error("off/foreign-route diagnostic")
					}
					return v2Reply(`{"data":{"settled":true}}`), nil
				})})
				var auth *Authorization
				var err error
				if route == "embeddings" {
					auth, err = c.AuthorizeEmbeddings(t.Context(), "key", &qtypes.EmbeddingRequest{Model: "fixture"}, 1)
				} else {
					auth, err = c.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{Model: "fixture"}, route)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = c.Refund(t.Context(), auth, 502, "upstream_error", 1, nil); err != nil {
					t.Fatal(err)
				}
				if calls != 2 {
					t.Fatal("send seam")
				}
			})
		}
	}
}

func TestShadowV2FailureDoesNotEscapeSend(t *testing.T) {
	setShadowRevision(t)
	saved := buildShadowTerminal
	t.Cleanup(func() { buildShadowTerminal = saved })
	buildShadowTerminal = func(*shadowAuthorization, Usage, string, string) map[string]any { panic("isolated diagnostic") }
	c, a := shadowAuth(t)
	a.shadowSettlement.v2 = true
	a.pinControlPlaneEndpoint(0)
	c.baseURLs = []string{"https://trustedrouter.com"}
	c.httpc = &http.Client{Transport: shadowV2Transport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get(shadowSettlementHeader) != "" {
			t.Error("panic emitted header")
		}
		return v2Reply(`{"data":{"settled":true}}`), nil
	})}
	if _, err := c.Settle(t.Context(), a, shadowUsage()); err != nil {
		t.Fatal("shadow error escaped settle", err)
	}
	if err := c.Refund(t.Context(), a, 502, "upstream_error", 1, nil); err != nil {
		t.Fatal("shadow error escaped refund", err)
	}
}

func TestShadowV2CertificateLimitBeforeDecode(t *testing.T) {
	var proof string
	for _, v := range shadowV2Variants(t, "exclusion_certificate") {
		if v2String(t, v["name"]) == "maximum-claims-kid-64" {
			proof = v2String(t, v["certificate"])
		}
	}
	parts := strings.Split(proof, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	h := v2Object(t, header)
	kid := v2String(t, h["kid"])
	h["kid"], _ = json.Marshal(kid[:len(kid)-1])
	header, _ = canonicalShadow(h)
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	claims := v2Object(t, payload)
	claims["invocation_nonce"], _ = json.Marshal(v2String(t, claims["invocation_nonce"]) + "x")
	payload, _ = canonicalShadow(claims)
	parts[0], parts[1] = base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload)
	proof = strings.Join(parts, ".")
	if len(proof) != 2049 {
		t.Fatal("synthetic one-byte control", len(proof))
	}
	if _, ok := shadowCertificateClaims(proof); ok {
		t.Fatal("certificate limit raised")
	}
}

func TestShadowV2LegacyBodyLiteral(t *testing.T) {
	raw, err := os.ReadFile("testdata/async_off_main/chat.completions.json")
	if err != nil {
		t.Fatal(err)
	}
	var transcript []map[string]json.RawMessage
	if json.Unmarshal(raw, &transcript) != nil {
		t.Fatal("transcript")
	}
	want := ""
	for _, row := range transcript {
		var path string
		_ = json.Unmarshal(row["path"], &path)
		if path == "/internal/gateway/settle" {
			want = v2String(t, row["body"])
			break
		}
	}
	for _, excluded := range []bool{false, true} {
		c, a := shadowAuth(t)
		a.AuthorizationID = "auth-oracle"
		a.Model = "test-model"
		a.EndpointID = "endpoint-oracle"
		a.pinControlPlaneEndpoint(0)
		if excluded {
			a.shadowSettlement = &shadowAuthorization{v2: true, exclusion: &shadowExclusion{certificate: "diagnostic", authorization: a.AuthorizationID, route: "chat.completions"}}
		}
		c.baseURLs = []string{"https://trustedrouter.com"}
		c.httpc = &http.Client{Transport: shadowV2Transport(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			if string(body) != want {
				t.Error("settle body differs from frozen main")
			}
			return v2Reply(`{"data":{"settled":true}}`), nil
		})}
		_, err = c.Settle(t.Context(), a, Usage{InputTokens: 3, OutputTokens: 2, RouteType: "chat.completions", SelectedEndpoint: "endpoint-oracle", RequestID: "request-oracle", ElapsedSeconds: 1, CacheReadInputTokens: 1})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestShadowV2IdentityRetentionVectors(t *testing.T) {
	for _, v := range shadowV2Variants(t, "wire_rejections") {
		name := v2String(t, v["name"])
		if !strings.HasPrefix(name, "server-identity-") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			identity := v2Object(t, v["expected_identity"])
			a := v2Authorization(t, shadowV2Variants(t, "authorize_excluded")[0])
			a.AuthorizationID = v2String(t, identity["authorization_id"])
			a.GenerationID = v2String(t, identity["generation_id"])
			a.WorkspaceID = v2String(t, identity["workspace_id"])
			a.APIKeyHash = v2String(t, identity["key_id"])
			a.InvocationNonce = v2String(t, identity["invocation_nonce"])
			a.CreditReservationID = v2String(t, identity["reservation_id"])
			c := fixtureClient()
			c.asyncShadow = true
			c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			known := map[string]bool{"authorization_id": true, "generation_id": true, "workspace_id": true, "key_id": true, "invocation_nonce": true, "reservation_id": true}
			if (a.shadowSettlement == nil) != known[strings.TrimPrefix(name, "server-identity-")] {
				t.Fatal("local identity agreement")
			}
		})
	}
}

func TestShadowV2ExcludedContradictionsAndOverflow(t *testing.T) {
	setShadowRevision(t)
	for _, damage := range []string{"binding", "empty", "null", "object", "size"} {
		t.Run(damage, func(t *testing.T) {
			a := v2Authorization(t, shadowV2Variants(t, "authorize_excluded")[0])
			switch damage {
			case "binding":
				a.BillingShadowBinding = "contradictory"
			case "empty":
				a.BillingShadowExclusion = json.RawMessage(`""`)
			case "null":
				a.BillingShadowExclusion = json.RawMessage(`null`)
			case "object":
				a.BillingShadowExclusion = json.RawMessage(`{}`)
			case "size":
				a.BillingShadowExclusion, _ = json.Marshal(strings.Repeat("A", 2049))
			}
			c := fixtureClient()
			c.asyncShadow = true
			c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			if a.shadowSettlement != nil {
				t.Fatal("malformed v2 retained")
			}
			a.pinControlPlaneEndpoint(0)
			c.baseURLs = []string{"https://trustedrouter.com"}
			calls := 0
			c.httpc = &http.Client{Transport: shadowV2Transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get(shadowSettlementHeader) != "" {
					t.Error("malformed v2 sent")
				}
				return v2Reply(`{"data":{"settled":true}}`), nil
			})}
			if _, err := c.Settle(t.Context(), a, fixtureUsage()); err != nil {
				t.Fatal(err)
			}
			if err := c.Refund(t.Context(), a, 502, "upstream_error", 1, nil); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatal("legacy lost")
			}
		})
	}
}

func TestShadowV2OutOfCohortEcho(t *testing.T) {
	old := ShadowBuildRevision
	ShadowBuildRevision = strings.Repeat("a", 40)
	t.Cleanup(func() { ShadowBuildRevision = old })
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	for _, route := range []string{"messages", "embeddings", "images", "videos", "decide", "audio.speech", "responses"} {
		t.Run(route, func(t *testing.T) {
			a := v2Authorization(t, shadowV2Variants(t, "authorize_excluded")[0])
			proof := v2String(t, a.BillingShadowExclusion)
			parts := strings.Split(proof, ".")
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			claims := v2Object(t, raw)
			claims["requested_route"], _ = json.Marshal(route)
			raw, _ = canonicalShadow(claims)
			parts[1] = base64.RawURLEncoding.EncodeToString(raw)
			proof = strings.Join(parts, ".")
			a.BillingShadowExclusion, _ = json.Marshal(proof)
			a.AdditionalCostReservationMicrodollars = 1
			reply, _ := json.Marshal(map[string]any{"data": v2WireAuthorization(a)})
			var headers []string
			c := New("https://trustedrouter.com", "test", &http.Client{Transport: shadowV2Transport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/internal/gateway/authorize" {
					if r.Header.Get(shadowPolicyHeader) != shadowPolicyV2 {
						t.Error("unsupported route capability")
					}
					return v2Reply(string(reply)), nil
				}
				headers = append(headers, r.Header.Get(shadowSettlementHeader))
				if r.Header.Get(asyncSettlementHeader) != "" {
					t.Error("terminal mode")
				}
				return v2Reply(`{"data":{"settled":true}}`), nil
			})})
			var auth *Authorization
			var err error
			if route == "embeddings" {
				auth, err = c.AuthorizeEmbeddings(t.Context(), "key", &qtypes.EmbeddingRequest{Model: "fixture"}, 1)
			} else {
				auth, err = c.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{Model: "fixture"}, route)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Refund(t.Context(), auth, 502, "upstream_error", 1, nil); err != nil {
				t.Fatal(err)
			}
			u := fixtureUsage()
			u.RouteType = route
			auth.RecordShadowInvocation(u.SelectedEndpoint, "openai")
			if _, err = c.Settle(t.Context(), auth, u); err != nil {
				t.Fatal(err)
			}
			if err = c.Refund(t.Context(), auth, 502, "upstream_error", 1, nil); err != nil {
				t.Fatal(err)
			}
			for i, header := range headers {
				if header == "" {
					t.Fatal("out-of-cohort echo absent")
				}
				fixture := "terminal_excluded_refund"
				if i == 1 {
					fixture = "terminal_excluded_settle"
				}
				v := shadowV2Variants(t, fixture)[0]
				expected := v2Object(t, v["object"])
				expected["certificate"], _ = json.Marshal(proof)
				attempt := v2Object(t, expected["attempt"])
				attempt["route_type"], _ = json.Marshal(route)
				if i == 2 {
					attempt["selected_endpoint"], _ = json.Marshal(u.SelectedEndpoint)
					attempt["adapter"] = json.RawMessage(`"openai"`)
				}
				expected["attempt"], _ = canonicalShadow(attempt)
				want, _ := canonicalShadow(expected)
				actual, _ := base64.RawURLEncoding.DecodeString(header)
				if !bytes.Equal(actual, want) {
					t.Fatal("out-of-cohort fixture-derived bytes")
				}
			}
		})
	}
}

func TestShadowV2MalformedBindingPresence(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	for _, binding := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`{}`), json.RawMessage(`123`), json.RawMessage(`""`)} {
		t.Run(string(binding), func(t *testing.T) {
			a := v2Authorization(t, shadowV2Variants(t, "authorize_excluded")[0])
			raw, _ := json.Marshal(v2WireAuthorization(a))
			response := v2Object(t, raw)
			response["billing_shadow_binding"] = binding
			raw, _ = json.Marshal(map[string]any{"data": response})
			c := New("https://trustedrouter.com", "test", &http.Client{Transport: shadowV2Transport(func(*http.Request) (*http.Response, error) { return v2Reply(string(raw)), nil })})
			auth, err := c.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{Model: "fixture"}, "chat.completions")
			if err != nil {
				t.Fatal("diagnostic changed legacy authorize", err)
			}
			if auth.shadowSettlement != nil {
				t.Fatal("contradictory binding disappeared in tolerant decoding")
			}
		})
	}
}

func TestShadowV2TransportRetry(t *testing.T) {
	setShadowRevision(t)
	for _, excluded := range []bool{false, true} {
		for _, kind := range []string{"settle", "refund"} {
			t.Run(fmt.Sprintf("%v/%s", excluded, kind), func(t *testing.T) {
				name := "authorize_compared"
				if excluded {
					name = "authorize_excluded"
				}
				a := v2Authorization(t, shadowV2Variants(t, name)[0])
				c := fixtureClient()
				c.asyncShadow = true
				c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
				a.pinControlPlaneEndpoint(0)
				u := shadowUsage()
				a.RecordShadowInvocation(u.SelectedEndpoint, "openai")
				c.baseURLs = []string{"https://trustedrouter.com", "https://aws.trustedrouter.com"}
				var headers, bodies []string
				c.httpc = &http.Client{Transport: shadowV2Transport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host != "trustedrouter.com" {
						t.Error("authority moved")
					}
					raw, _ := io.ReadAll(r.Body)
					headers = append(headers, r.Header.Get(shadowSettlementHeader))
					bodies = append(bodies, string(raw))
					if len(headers) == 1 {
						return nil, io.ErrUnexpectedEOF
					}
					return v2Reply(`{"data":{"settled":true}}`), nil
				})}
				if kind == "settle" {
					if _, err := c.Settle(t.Context(), a, u); err != nil {
						t.Fatal("existing transport retry", err)
					}
					if _, err := c.Settle(t.Context(), a, u); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := c.Refund(t.Context(), a, 502, "upstream_error", 1, nil); err == nil {
						t.Fatal("legacy refund error lost")
					}
					if err := c.Refund(t.Context(), a, 502, "upstream_error", 1, nil); err != nil {
						t.Fatal(err)
					}
				}
				expected := 2
				if kind == "settle" {
					expected = 3
				}
				if len(headers) != expected {
					t.Fatal("retry policy changed", len(headers))
				}
				for i := range headers {
					if headers[i] == "" || headers[i] != headers[0] || bodies[i] != bodies[0] {
						t.Fatal("retry bytes changed")
					}
				}
			})
		}
	}
}

// Test-only wire projection: production Authorization deliberately ignores v2
// fields during JSON decoding. Keep the original test response bytes/meaning.
func v2WireAuthorization(a *Authorization) map[string]json.RawMessage {
	raw, _ := json.Marshal(a)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if len(a.BillingShadowPolicy) > 0 {
		fields["billing_shadow_policy"] = a.BillingShadowPolicy
	}
	if len(a.BillingShadowExclusion) > 0 {
		fields["billing_shadow_exclusion"] = a.BillingShadowExclusion
	}
	return fields
}
