package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf16"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var shadowIdentityNames = []string{"billing_shadow_policy", "billing_shadow_exclusion", "billing_shadow_binding"}

// No recognition model: encoding/json is the oracle. Binding must also select
// the field in the real legacy authorize target (whose decode tags stay intact).
func shadowDecoderIdentity(t *testing.T, key string) uint8 {
	t.Helper()
	raw := []byte(`{` + key + `:"recognized"}`)
	var target struct {
		Policy    string `json:"billing_shadow_policy"`
		Exclusion string `json:"billing_shadow_exclusion"`
		Binding   string `json:"billing_shadow_binding"`
	}
	var legacy struct {
		Data Authorization `json:"data"`
	}
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(append(append([]byte(`{"data":`), raw...), '}'), &legacy); err != nil {
		t.Fatal(err)
	}
	if (target.Binding != "") != (legacy.Data.BillingShadowBinding != "") {
		t.Fatal("test tags disagree with real legacy target")
	}
	var identity uint8
	for i, value := range []string{target.Policy, target.Exclusion, string(legacy.Data.BillingShadowBinding)} {
		if value != "" {
			identity |= 1 << i
		}
	}
	return identity
}

func shadowFoldOrbit(r rune) []rune {
	orbit := []rune{r}
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		orbit = append(orbit, next)
	}
	return orbit
}

// JSON tokens, including deliberately invalid UTF-8 which json.Unmarshal repairs.
// Orbits are computed from this toolchain's Unicode tables, never a fixed list.
func shadowIdentityCorpus(name string) []string {
	keys := map[string]bool{}
	add := func(runes []rune) {
		raw, _ := json.Marshal(string(runes))
		keys[string(raw)] = true
		var escaped strings.Builder
		escaped.WriteByte('"')
		for _, r := range runes {
			if r <= 0xffff {
				fmt.Fprintf(&escaped, `\u%04x`, r)
			} else {
				a, b := utf16.EncodeRune(r)
				fmt.Fprintf(&escaped, `\u%04x\u%04x`, a, b)
			}
		}
		escaped.WriteByte('"')
		keys[escaped.String()] = true
	}
	runes := []rune(name)
	add(runes)
	for i, r := range runes {
		for _, folded := range shadowFoldOrbit(r) {
			variant := append([]rune(nil), runes...)
			variant[i] = folded
			add(variant)
		}
		// Insertions, deletions and swaps at every position, including swaps which
		// leave equal characters unchanged: the decoder, not this generator, decides.
		add(append(append(append([]rune(nil), runes[:i]...), 'x'), runes[i:]...))
		add(append(append([]rune(nil), runes[:i]...), runes[i+1:]...))
		for j := i + 1; j < len(runes); j++ {
			variant := append([]rune(nil), runes...)
			variant[i], variant[j] = variant[j], variant[i]
			add(variant)
			if len(shadowFoldOrbit(r)) > 2 && len(shadowFoldOrbit(runes[j])) > 2 {
				for _, a := range shadowFoldOrbit(r) {
					for _, b := range shadowFoldOrbit(runes[j]) {
						variant := append([]rune(nil), runes...)
						variant[i], variant[j] = a, b
						add(variant)
					}
				}
			}
		}
	}
	for _, separator := range []string{"-", ".", " ", "", "＿"} {
		add([]rune(strings.ReplaceAll(name, "_", separator)))
	}
	full := []rune(name)
	for i, r := range full {
		if r >= '!' && r <= '~' {
			full[i] = r + 0xfee0
		}
	}
	add(full)
	for _, suffix := range []string{"\u0301", "\x00", "x"} {
		add([]rune(name + suffix))
	}
	keys[`"`+name+`\ud800"`] = true
	keys[`"`+name+string([]byte{0xff})+`"`] = true
	keys[`"`+string([]byte{0xff})+name[1:]+`"`] = true
	for _, length := range []int{159, 160, 161, 320} {
		keys[`"`+name+strings.Repeat("x", length-len(name)-2)+`"`] = true
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func TestShadowV2IdentityDecoderDifferential(t *testing.T) {
	total, matched := 0, 0
	for _, name := range shadowIdentityNames {
		t.Run(name, func(t *testing.T) {
			for _, key := range shadowIdentityCorpus(name) {
				want := shadowDecoderIdentity(t, key)
				var capture shadowCapture
				raw := []byte(`{"data":{` + key + `:"recognized"}}`)
				// Byte-at-a-time delivery includes boundaries within UTF-8 and escapes.
				for _, b := range raw {
					_, _ = capture.Write([]byte{b})
				}
				if capture.seen != want {
					t.Fatalf("key %q: capture identity %d, decoder identity %d", key, capture.seen, want)
				}
				total++
				if want != 0 {
					matched++
				}
			}
		})
	}
	t.Logf("%d decoder-oracle keys, %d matched spellings", total, matched)
}

// All ordered pairs of decoder-matched corpus spellings, with equal values and
// both different-value orders, on both real seams and both terminal senders.
// No-policy results compare with the corresponding frozen-main plain-key cell.
func TestShadowV2IdentityDuplicateSenders(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	setShadowRevision(t)
	raw, err := os.ReadFile("testdata/async_live_main/duplicates.json")
	if err != nil {
		t.Fatal(err)
	}
	frozen := map[string]duplicateOracleRow{}
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	cases := duplicateOracleCases(t)
	total := 0
	for member, name := range shadowIdentityNames {
		kind := "excluded"
		if member == 2 {
			kind = "compared"
		}
		projection := duplicateFixture(t, "authorize_"+kind)
		keys := []string{}
		for _, key := range shadowIdentityCorpus(name) {
			if shadowDecoderIdentity(t, key) == 1<<member {
				keys = append(keys, key)
			}
		}
		for _, noPolicy := range []bool{false, true} {
			if member == 0 && noPolicy {
				continue
			} // A present policy member selects the policy path, even when malformed.
			for _, planned := range []bool{false, true} {
				for _, order := range []string{"identical", "valid-bad", "bad-valid"} {
					t.Run(fmt.Sprintf("%s/no-policy=%t/plan=%t/%s", name, noPolicy, planned, order), func(t *testing.T) {
						cellName := fmt.Sprintf("members/%s/%s/%s/plain/no-policy=%t", kind, name, order, noPolicy)
						template := cases[cellName].reply
						value1, value2 := string(projection[name]), string(projection[name])
						if order == "valid-bad" {
							value2 = `"bad"`
						}
						if order == "bad-valid" {
							value1 = `"bad"`
						}
						token := `"` + name + `"`
						tail := strings.TrimPrefix(template, `{"data":{`+token+`:`+value1+`,`+token+`:`+value2+`,`)
						if tail == template {
							t.Fatal("missing canonical duplicate template")
						}
						expected, ok := frozen[fmt.Sprintf("%s/shadow=true/plan=%t", cellName, planned)]
						if !ok {
							t.Fatal("missing main reference")
						}
						for _, field := range []*json.RawMessage{&expected.Authorization, &expected.Retention} {
							var b bytes.Buffer
							if err := json.Compact(&b, *field); err != nil {
								t.Fatal(err)
							}
							*field = b.Bytes()
						}
						var reply string
						var headers, bodies []string
						c := New("https://trustedrouter.com", "test", &http.Client{Transport: liveOracleTransport(func(r *http.Request) (*http.Response, error) {
							if r.URL.Path == "/internal/gateway/authorize" {
								return v2Reply(reply), nil
							}
							var body bytes.Buffer
							if _, err := body.ReadFrom(r.Body); err != nil {
								t.Fatal(err)
							}
							bodies = append(bodies, body.String())
							headers = append(headers, r.Header.Get(shadowSettlementHeader))
							return v2Reply(`{"data":{"settled":true,"cost_microdollars":2}}`), nil
						})})
						c.asyncShadow = true
						for _, first := range keys {
							for _, last := range keys {
								reply = `{"data":{` + first + `:` + value1 + `,` + last + `:` + value2 + `,` + tail
								headers, bodies = nil, nil
								inv := &authorizationInvocation{nonce: "fixed"}
								inv.once.Do(func() {})
								ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, inv)
								var plan *SpendLeaseAdmissionPlan
								if planned {
									plan = &SpendLeaseAdmissionPlan{key: "key", body: []byte(`{}`)}
									inv.plans = map[string]*SpendLeaseAdmissionPlan{"key": plan}
								}
								a, endpoint, err := c.authorizeAtDecodeSeamWithAdmission(ctx, "lookup", map[string]any{}, spendlease.EstimateRequest{}, plan)
								if err != nil {
									t.Fatalf("%q / %q: %v", first, last, err)
								}
								authorization, _ := json.Marshal(a)
								c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
								retention := duplicateRetention(a)
								u := shadowUsage()
								u.InputTokens, u.OutputTokens = 1, 1
								a.RecordShadowInvocation(u.SelectedEndpoint, "openai")
								_, settleErr := c.Settle(ctx, a, u)
								refundErr := c.Refund(ctx, a, 502, "upstream_error", 1, nil)
								if len(headers) != 2 {
									t.Fatal("both real senders must run")
								}
								if !noPolicy {
									if string(a.BillingShadowPolicy) != "null" || a.shadowSettlement != nil || headers[0] != "" || headers[1] != "" {
										t.Fatalf("%q / %q: duplicate emitted or retained diagnostic", first, last)
									}
								} else {
									if len(a.BillingShadowPolicy) != 0 || len(a.BillingShadowExclusion) != 0 || a.shadowBindingPresent {
										t.Fatal("no-policy captured metadata")
									}
									// These are byte-for-byte main's frozen legacy fields, retention, money
									// bodies and errors for the same decoded values, independent of spelling.
									row := duplicateOracleRow{Authorization: authorization, Endpoint: endpoint, Error: "<nil>", ErrorType: "<nil>", ErrorValue: "<nil>", Retention: retention, Bodies: bodies, SendErrors: []string{fmt.Sprint(settleErr), fmt.Sprint(refundErr)}}
									if !reflect.DeepEqual(row, expected) {
										t.Fatalf("%q / %q: no-policy differs from frozen main\ngot %+v\nwant %+v", first, last, row, expected)
									}
									for _, h := range headers {
										if h != "" && string(decodeShadow(t, h)["v"]) != "1" {
											t.Fatal("no-policy emitted v2")
										}
									}
								}
								if settleErr != nil || refundErr != nil {
									t.Fatalf("send errors %v / %v", settleErr, refundErr)
								}
								total++
							}
						}
					})
				}
			}
		}
	}
	t.Logf("%d ordered duplicate/seam/value/policy scenarios; %d real terminal sends", total, 2*total)
}
