package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Source-compatible with frozen main 35e91368. Only this main-compatible test
// generates duplicates.json, in a disposable main tree, never on head.
type duplicateOracleCase struct {
	reply string
	// Per legacy target: v1, suppressed, ambiguous, compared or excluded.
	ordinary, plan string
}
type duplicateOracleRow struct {
	Authorization                json.RawMessage
	Error, ErrorType, ErrorValue string
	Endpoint                     int
	Retention                    json.RawMessage
	Bodies                       []string
	SendErrors                   []string
}

func duplicateFixture(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "async_settlement", "shadow_v2", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Variants []struct {
			Object map[string]json.RawMessage `json:"object"`
		} `json:"variants"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Variants[0].Object
}
func duplicateOracleCases(t *testing.T) map[string]duplicateOracleCase {
	t.Helper()
	_, a := shadowAuth(t)
	a.IdempotentReplay = false
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]duplicateOracleCase{}
	for name, prefix := range map[string]string{
		"control":       "",
		"wrong-policy":  `"data":{"billing_shadow_policy":"wrong"},`,
		"bad-exclusion": `"data":{"billing_shadow_policy":"shadow-v2","billing_shadow_exclusion":"bad"},`,
		"binding":       `"data":{"billing_shadow_binding":"discarded"},`,
	} {
		ordinary := "v1"
		if name == "wrong-policy" || name == "bad-exclusion" {
			ordinary = "suppressed"
		}
		cases["data/"+name] = duplicateOracleCase{`{` + prefix + `"data":` + string(raw) + `}`, ordinary, "v1"}
	}
	for _, kind := range []string{"compared", "excluded"} {
		// Overlay the unchanged positive projection onto the legacy identities, just
		// as the existing fixture sender does. Never rewrite a signed fixture.
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, "billing_shadow_binding")
		projection := duplicateFixture(t, "authorize_"+kind)
		for k, v := range projection {
			fields[k] = v
		}
		positive, _ := json.Marshal(fields)
		cases["positive/"+kind] = duplicateOracleCase{`{"data":` + string(positive) + `}`, kind, kind}
		// Different members split across ordinary objects are still positive.
		for _, policyFirst := range []bool{false, true} {
			for _, middle := range []string{"", `"data":{},`} {
				withoutPolicy := map[string]json.RawMessage{}
				for k, v := range fields {
					if k != "billing_shadow_policy" {
						withoutPolicy[k] = v
					}
				}
				evidence, _ := json.Marshal(withoutPolicy)
				first, last := `{"billing_shadow_policy":"shadow-v2"}`, string(evidence)
				planMode := "v1"
				if !policyFirst {
					first, last = last, first
					planMode = "suppressed"
				}
				name := fmt.Sprintf("split/%s/policy-first=%t/three=%t", kind, policyFirst, middle != "")
				cases[name] = duplicateOracleCase{`{"data":` + first + `,` + middle + `"data":` + last + `}`, kind, planMode}
			}
		}

		for _, field := range []string{"billing_shadow_policy", "billing_shadow_exclusion", "billing_shadow_binding"} {
			valid, exists := projection[field]
			if !exists {
				continue
			}
			// Ordinary struct decoding merges all data objects; plan RawMessage
			// decoding selects the last one. Freeze main for both interpretations.
			for _, count := range []int{2, 3} {
				for _, noPolicy := range []bool{false, true} {
					if noPolicy && field == "billing_shadow_policy" {
						continue
					}
					lastFields := map[string]json.RawMessage{}
					for k, v := range fields {
						lastFields[k] = v
					}
					ordinary, planMode := "ambiguous", kind
					if noPolicy {
						delete(lastFields, "billing_shadow_policy")
						ordinary, planMode = "v1", "v1"
					}
					last, _ := json.Marshal(lastFields)
					prefix := strings.Repeat(`"data":{"`+field+`":`+string(valid)+`},`, count-1)
					name := fmt.Sprintf("merged/%s/%s/objects=%d/no-policy=%t", kind, field, count, noPolicy)
					cases[name] = duplicateOracleCase{`{` + prefix + `"data":` + string(last) + `}`, ordinary, planMode}
				}
			}
			for _, noPolicy := range []bool{false, true} {
				if noPolicy && field == "billing_shadow_policy" {
					continue
				}
				base := map[string]json.RawMessage{}
				for k, v := range fields {
					base[k] = v
				}
				delete(base, field)
				if noPolicy {
					delete(base, "billing_shadow_policy")
				}
				tail, _ := json.Marshal(base)
				for _, order := range []string{"valid-bad", "bad-valid", "identical"} {
					first, last := string(valid), `"bad"`
					if order == "bad-valid" {
						first, last = last, first
					}
					if order == "identical" {
						last = first
					}
					for _, spelling := range []string{"plain", "escaped-first", "escaped-last", "case-last", "fully-escaped-last"} {
						k1, k2 := `"`+field+`"`, `"`+field+`"`
						escaped := `"\u0062` + field[1:] + `"`
						switch spelling {
						case "escaped-first":
							k1 = escaped
						case "escaped-last":
							k2 = escaped
						case "case-last":
							k2 = `"` + strings.ToUpper(field) + `"`
						case "fully-escaped-last":
							k2 = `"`
							for _, r := range field {
								k2 += fmt.Sprintf(`\u%04x`, r)
							}
							k2 += `"`
						}
						mode := "ambiguous"
						if noPolicy {
							mode = "v1"
						}
						name := fmt.Sprintf("members/%s/%s/%s/%s/no-policy=%t", kind, field, order, spelling, noPolicy)
						reply := `{"data":{` + k1 + `:` + first + `,` + k2 + `:` + last + `,` + string(tail[1:]) + `}`
						cases[name] = duplicateOracleCase{reply, mode, mode}
					}
				}
			}
		}
	}
	return cases
}

func duplicateRetention(a *Authorization) json.RawMessage {
	state := map[string]any{"retained": a.shadowSettlement != nil, "async": a.async != nil}
	if s := a.shadowSettlement; s != nil {
		state["raw"], state["full"], state["proof"], state["terminal"], state["requested"] = s.raw, s.full, s.proof, s.terminal, s.requested
	}
	raw, _ := json.Marshal(state)
	return raw
}

func TestAsyncLiveDuplicateFrozenMain(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	setShadowRevision(t)
	generate := os.Getenv("GENERATE_FROZEN_MAIN_ORACLE") == "1"
	path := filepath.Join("testdata", "async_live_main", "duplicates.json")
	want := map[string]duplicateOracleRow{}
	if !generate {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]duplicateOracleRow{}
	for name, cell := range duplicateOracleCases(t) {
		for _, shadow := range []bool{false, true} {
			for _, planned := range []bool{false, true} {
				key := fmt.Sprintf("%s/shadow=%t/plan=%t", name, shadow, planned)
				t.Run(key, func(t *testing.T) {
					var bodies, headers, sendErrors []string
					c := New("https://trustedrouter.com", "test", &http.Client{Transport: liveOracleTransport(func(r *http.Request) (*http.Response, error) {
						reply := cell.reply
						if r.URL.Path != "/internal/gateway/authorize" {
							raw, err := io.ReadAll(r.Body)
							if err != nil {
								t.Fatal(err)
							}
							bodies = append(bodies, string(raw))
							headers = append(headers, r.Header.Get(shadowSettlementHeader))
							if r.Header.Get(asyncSettlementHeader) != "" {
								t.Error("legacy money path bound async")
							}
							reply = `{"data":{"settled":true,"cost_microdollars":2}}`
						}
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(reply))}, nil
					})})
					c.asyncShadow = shadow
					inv := &authorizationInvocation{nonce: "fixed"}
					inv.once.Do(func() {})
					ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, inv)
					var plan *SpendLeaseAdmissionPlan
					if planned {
						plan = &SpendLeaseAdmissionPlan{key: "key", body: []byte(`{}`)}
						inv.plans = map[string]*SpendLeaseAdmissionPlan{"key": plan}
					}
					a, endpoint, err := c.authorizeAtDecodeSeamWithAdmission(ctx, "lookup", map[string]any{}, spendlease.EstimateRequest{}, plan)
					row := duplicateOracleRow{Endpoint: endpoint, Error: fmt.Sprint(err), ErrorType: fmt.Sprintf("%T", err), ErrorValue: fmt.Sprintf("%#v", err), Retention: json.RawMessage(`null`)}
					row.Authorization, _ = json.Marshal(a)
					mode := cell.ordinary
					if planned {
						mode = cell.plan
					}
					if !shadow {
						mode = "v1"
					}
					if a != nil {
						// Compare every legacy field, including private fields. The three new
						// capture fields are checked separately below; they never enter money.
						if !generate {
							var expected *Authorization
							var compact bytes.Buffer
							if err := json.Compact(&compact, want[key].Authorization); err != nil {
								t.Fatal(err)
							}
							if err := json.Unmarshal(compact.Bytes(), &expected); err != nil {
								t.Fatal(err)
							}
							av, ev := reflect.ValueOf(a).Elem(), reflect.ValueOf(expected).Elem()
							for i := 0; i < av.NumField(); i++ {
								n := av.Type().Field(i).Name
								if n == "BillingShadowPolicy" || n == "BillingShadowExclusion" || n == "shadowBindingPresent" {
									continue
								}
								x, y := av.Field(i), ev.Field(i)
								if x.CanInterface() {
									if !reflect.DeepEqual(x.Interface(), y.Interface()) {
										t.Fatalf("legacy field %s differs from main", n)
									}
								} else if !x.IsZero() || !y.IsZero() {
									t.Fatalf("unexpected private decode state %s", n)
								}
							}
						}
						c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
						row.Retention = duplicateRetention(a)
						if !generate {
							if mode == "ambiguous" || mode == "suppressed" {
								if a.shadowSettlement != nil {
									t.Fatal("ambiguous/malformed metadata retained diagnostics")
								}
							}
							if mode == "ambiguous" {
								v := reflect.ValueOf(a).Elem()
								if string(v.FieldByName("BillingShadowPolicy").Bytes()) != "null" || !v.FieldByName("BillingShadowExclusion").IsZero() || !v.FieldByName("shadowBindingPresent").IsZero() {
									t.Fatal("a duplicate was selected as evidence")
								}
							}
							if mode == "v1" {
								v := reflect.ValueOf(a).Elem()
								for _, n := range []string{"BillingShadowPolicy", "BillingShadowExclusion", "shadowBindingPresent"} {
									if !v.FieldByName(n).IsZero() {
										t.Fatalf("no-policy metadata %s", n)
									}
								}
							}
						}
						// BOTH real terminal senders run for every successfully decoded cell.
						// Record the terminal endpoint through the real recorder when available.
						// Main predates that method; its legacy body remains identical.
						u := shadowUsage()
						u.InputTokens, u.OutputTokens = 1, 1
						if recorder, ok := any(a).(interface{ RecordShadowInvocation(string, string) }); ok {
							recorder.RecordShadowInvocation(u.SelectedEndpoint, "openai")
						}
						_, err = c.Settle(ctx, a, u)
						sendErrors = append(sendErrors, fmt.Sprint(err))
						err = c.Refund(ctx, a, 502, "upstream_error", 1, nil)
						sendErrors = append(sendErrors, fmt.Sprint(err))
						if len(bodies) != 2 {
							t.Fatalf("real terminal send count %d", len(bodies))
						}
						if !generate {
							for _, h := range headers {
								switch mode {
								case "ambiguous", "suppressed":
									if h != "" {
										t.Fatal("ambiguous/malformed metadata emitted a diagnostic")
									}
								case "compared", "excluded":
									if h == "" {
										t.Fatal("positive fixture lost diagnostic")
									}
									v := decodeShadow(t, h)
									if string(v["v"]) != "2" || string(v["variant"]) != `"`+mode+`"` {
										t.Fatalf("wrong v2 diagnostic %s", h)
									}
								case "v1":
									if (h != "") != (a.shadowSettlement != nil) {
										t.Fatal("main v1 header presence changed")
									}
									if h != "" {
										v := decodeShadow(t, h)
										if _, ok := v["variant"]; ok {
											t.Fatal("no-policy authorization emitted v2")
										}
									}
								}
							}
						}
					}
					row.Bodies, row.SendErrors = bodies, sendErrors
					got[key] = row
					if !generate {
						expected, ok := want[key]
						if !ok {
							t.Fatal("missing main cell")
						}
						for _, r := range []*json.RawMessage{&expected.Authorization, &expected.Retention} {
							var b bytes.Buffer
							if err := json.Compact(&b, *r); err != nil {
								t.Fatal(err)
							}
							*r = b.Bytes()
						}
						// Independently replay main retention from the decoded legacy fields
						// for every cell, including intentional v2 suppression/upgrades.
						if a != nil {
							var legacy Authorization
							if err := json.Unmarshal(row.Authorization, &legacy); err != nil {
								t.Fatal(err)
							}
							c.retainShadowAuthorization(&legacy, &qtypes.OpenAIChatRequest{}, "chat.completions")
							if !bytes.Equal(duplicateRetention(&legacy), expected.Retention) {
								t.Fatal("legacy retention differs from frozen main")
							}
						}
						// Main's retention is frozen for every input. Explicit policy-bearing
						// cells intentionally suppress/upgrade diagnostics; all no-policy cells
						// must retain main's exact state, including duplicate non-policy members.
						if mode != "v1" {
							row.Retention = expected.Retention
						}
						if !reflect.DeepEqual(row, expected) {
							t.Fatalf("main differential mismatch\ngot %+v\nwant %+v", row, expected)
						}
					}
				})
			}
		}
	}
	if generate {
		raw, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	} else if len(got) != len(want) {
		t.Fatalf("main cell inventory %d != %d", len(got), len(want))
	}
}
