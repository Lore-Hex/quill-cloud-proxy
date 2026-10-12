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

type liveOracleTransport func(*http.Request) (*http.Response, error)

func (f liveOracleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type liveOracleRow struct {
	Authorization    json.RawMessage
	Error, ErrorType string
	ErrorField       string
	Endpoint         int
	Retention        json.RawMessage
	RetentionAllocs  float64
}

// This file is deliberately source-compatible with main 35e91368. See the
// adjacent source.txt for capture provenance and regeneration instructions.
func TestAsyncLiveFrozenMain(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	cases := map[string]string{
		"no-policy-root-null-read-ahead": `null {"data":{"billing_shadow_policy":"shadow-v2"}}`,
		"no-policy-object-read-ahead":    `{} {"data":{"billing_shadow_policy":"shadow-v2"}}`,
		"missing-data":                   `{}`, "root-null": `null`, "null-data": `{"data":null}`, "empty-data": `{"data":{}}`,
		"F4-bool-data": `{"data":true}`, "F4-string-data": `{"data":"x"}`, "array-data": `{"data":[]}`, "number-data": `{"data":7}`,
		"F4-known-model-type": `{"data":{"model":3}}`, "unknown-fields": `{"unknown":true,"data":{"model":"x","unknown":{"x":[1,2]}}}`,
		"duplicate-known":        `{"data":{"model":"first","model":"last"}}`,
		"duplicate-data-null":    `{"data":{"model":"x"},"data":null}`,
		"duplicate-data-objects": `{"data":{"billing_shadow_binding":"x"},"data":{"model":"y"}}`,
		"duplicate-binding-null": `{"data":{"billing_shadow_binding":"a","billing_shadow_binding":null}}`,
		"malformed-binding":      `{"data":{"billing_shadow_binding":{},"model":"x"}}`,
		"truncated":              `{"data":`, "http-error-envelope": `{"error":{"message":"oops","type":"bad_request","reason":"test"}}`,
		"no-policy-huge-exclusion": `{"data":{"billing_shadow_exclusion":"` + strings.Repeat("x", 1000000) + `"}}`,
	}
	for _, name := range []string{"authorize_v1", "authorize_v1_builder"} {
		raw, err := os.ReadFile("testdata/async_settlement/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = string(raw)
	}
	for _, value := range []string{`null`, `true`, `123`, `{}`, `[]`, `"opaque"`} {
		cases["optional-"+value] = `{"data":{"billing_shadow_binding":` + value + `,"async_eligible":` + value + `,"billing_snapshot_hash":` + value + `}}`
	}
	a := fixtureAuthorization(t, true)
	a.IdempotentReplay = false
	raw, _ := json.Marshal(map[string]any{"data": a})
	cases["complete-valid"] = string(raw)
	// Retained snapshots exercise the same seam, including all reviewer boundaries.
	for _, size := range []int{5200, 6144, 6145} {
		_, a := shadowBoundaryAuthorization(t, size)
		raw, _ := json.Marshal(map[string]any{"data": a})
		cases[fmt.Sprintf("snapshot-%d", size)] = string(raw)
	}
	cases["F2-off-huge-v2-fields"] = `{"data":{"billing_shadow_policy":"` + strings.Repeat("x", 1000000) + `","billing_shadow_exclusion":"` + strings.Repeat("x", 1000000) + `"}}`
	name := "matrix.json"
	if liveOracleRace {
		name = "matrix-race.json"
	}
	path := filepath.Join("testdata", "async_live_main", name)
	want := map[string]liveOracleRow{}
	generate := os.Getenv("GENERATE_FROZEN_MAIN_ORACLE") == "1"
	if !generate {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]liveOracleRow{}
	for name, reply := range cases {
		for _, shadow := range []bool{false, true} {
			if shadow && name == "F2-off-huge-v2-fields" {
				continue
			}
			for _, planned := range []bool{false, true} {
				for _, status := range []int{200, 400} {
					key := fmt.Sprintf("%s/shadow=%t/plan=%t/status=%d", name, shadow, planned, status)
					t.Run(key, func(t *testing.T) {
						c := New("https://trustedrouter.com", "test", &http.Client{Transport: liveOracleTransport(func(r *http.Request) (*http.Response, error) {
							marker := r.Header.Get("X-TR-Settlement-Shadow-Policy")
							if !generate && (marker == "shadow-v2") != shadow {
								t.Error("authorize marker")
							}
							return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(reply))}, nil
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
						row := liveOracleRow{Endpoint: endpoint, Error: fmt.Sprint(err), ErrorType: fmt.Sprintf("%T", err)}
						if e, ok := err.(*json.UnmarshalTypeError); ok {
							row.ErrorField = e.Field
						}
						row.Authorization, _ = json.Marshal(a)
						if !generate {
							var expectedAuthorization *Authorization
							var compact bytes.Buffer
							if err := json.Compact(&compact, want[key].Authorization); err != nil {
								t.Fatal(err)
							}
							if err := json.Unmarshal(compact.Bytes(), &expectedAuthorization); err != nil {
								t.Fatal(err)
							}
							if !reflect.DeepEqual(a, expectedAuthorization) {
								t.Fatal("complete decoded Authorization differs from main, including private state")
							}
						}
						if a != nil {
							req := &qtypes.OpenAIChatRequest{}
							row.RetentionAllocs = testing.AllocsPerRun(3, func() { a.shadowSettlement = nil; c.retainShadowAuthorization(a, req, "chat.completions") })
							state := map[string]any{"retained": a.shadowSettlement != nil, "async": a.async != nil}
							if s := a.shadowSettlement; s != nil {
								state["raw"] = s.raw
								state["full"] = s.full
								state["proof"] = s.proof
								state["terminal"] = s.terminal
								state["requested"] = s.requested
							}
							// New private metadata must also remain dormant on every live-path cell.
							v := reflect.ValueOf(a).Elem()
							for _, name := range []string{"BillingShadowPolicy", "BillingShadowExclusion", "shadowBindingPresent"} {
								f := v.FieldByName(name)
								if f.IsValid() && !f.IsZero() {
									t.Errorf("live path retained %s", name)
								}
							}
							row.Retention, _ = json.Marshal(state)
						} else {
							row.Retention = json.RawMessage(`null`)
						}
						got[key] = row
						if !generate {
							expected, ok := want[key]
							if !ok {
								t.Fatal("missing frozen cell")
							}
							for _, raw := range []*json.RawMessage{&expected.Authorization, &expected.Retention} {
								var compact bytes.Buffer
								if err := json.Compact(&compact, *raw); err != nil {
									t.Fatal(err)
								}
								*raw = compact.Bytes()
							}
							// Map bucket overflow allocation varies with the runtime hash seed.
							// Compare 16-allocation classes; preserve the exact zero class.
							bucket := 16
							if liveOracleRace {
								bucket = 256
							} // race randomly discards pooled objects
							bound := float64((int(expected.RetentionAllocs) + bucket - 1) / bucket * bucket)
							if row.RetentionAllocs > bound {
								t.Errorf("retention allocations %g > main %g", row.RetentionAllocs, expected.RetentionAllocs)
							}
							row.RetentionAllocs = expected.RetentionAllocs
							if !reflect.DeepEqual(row, expected) {
								t.Errorf("main identity mismatch\ngot %+v\nwant %+v", row, expected)
							}
						}
					})
				}
			}
		}
	}
	if generate {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	} else if len(got) != len(want) {
		t.Fatalf("matrix inventory %d != %d", len(got), len(want))
	}
}

func TestAsyncLiveMainAllocationClass(t *testing.T) {
	// MAIN's decoder ignores arbitrarily large unknown v2 values: 152 B / 2
	// allocations with Go 1.24.13. Authorization itself is reused outside measure.
	for _, size := range []int{0, 1024, 1000000} {
		raw := []byte(`{"billing_shadow_policy":"` + strings.Repeat("x", size) + `","billing_shadow_exclusion":"` + strings.Repeat("x", size) + `"}`)
		var a Authorization
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				a = Authorization{}
				if err := json.Unmarshal(raw, &a); err != nil {
					b.Fatal(err)
				}
			}
		})
		bytesBound := int64(152)
		if liveOracleRace {
			bytesBound = 160
		}
		t.Logf("off optional size=%d: %d B / %d allocations", size, result.AllocedBytesPerOp(), result.AllocsPerOp())
		if result.AllocsPerOp() > 2 || result.AllocedBytesPerOp() > bytesBound {
			t.Fatalf("F2 size %d: %d B / %d allocs; main 152 / 2", size, result.AllocedBytesPerOp(), result.AllocsPerOp())
		}
		v := reflect.ValueOf(a)
		for _, name := range []string{"BillingShadowPolicy", "BillingShadowExclusion"} {
			f := v.FieldByName(name)
			if f.IsValid() && !f.IsZero() {
				t.Fatal("off metadata retained")
			}
		}
	}
	for _, size := range []int{6145, 65536, 65537} {
		a := &shadowAuthorization{raw: make([]byte, size)}
		// No snapshot at all: even entering the builder is invalid. Allocation
		// measurement independently catches implementations that tolerate nil DTOs.
		allocs := testing.AllocsPerRun(100, func() {
			if shadowSuccessFits(a) {
				t.Error("over-inline fit")
			}
		})
		if allocs != 0 {
			t.Fatalf("F3 over-inline %d allocated %g; main zero", size, allocs)
		}
	}
}
