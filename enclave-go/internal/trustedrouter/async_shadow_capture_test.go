package trustedrouter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func captureShadowProjection(a *Authorization, raw []byte) {
	var s shadowCapture
	_, _ = s.Write([]byte(`{"data":`))
	_, _ = s.Write(raw)
	_, _ = s.Write([]byte(`}`))
	s.finish(a)
}

func TestShadowV2BoundedCapture(t *testing.T) {
	for _, size := range []int{2048, 2049, 1000000} {
		for _, escaped := range []bool{false, true} {
			token := strings.Repeat("A", size)
			wire := token
			if escaped {
				wire = strings.Repeat(`\u0041`, size)
			}
			for _, policyFirst := range []bool{false, true} {
				fields := []string{`"billing_shadow_policy":"shadow-v2"`, `"billing_shadow_exclusion":"` + wire + `"`}
				if !policyFirst {
					fields[0], fields[1] = fields[1], fields[0]
				}
				raw := []byte(`{"data":{` + strings.Join(fields, ",") + `}}`)
				for _, chunk := range []int{1, 7, 512, len(raw)} {
					t.Run(fmt.Sprintf("%d/escaped=%v/first=%v/chunk=%d", size, escaped, policyFirst, chunk), func(t *testing.T) {
						var s shadowCapture
						for start := 0; start < len(raw); start += chunk {
							_, _ = s.Write(raw[start:min(start+chunk, len(raw))])
						}
						var a Authorization
						s.finish(&a)
						if string(a.BillingShadowPolicy) != `"shadow-v2"` {
							t.Fatal("policy lost")
						}
						var got string
						if err := json.Unmarshal(a.BillingShadowExclusion, &got); err != nil {
							t.Fatal(err)
						}
						if size <= 2048 {
							if got != token {
								t.Fatal("opaque certificate changed")
							}
						} else if got != "" || string(a.BillingShadowExclusion) != "null" {
							t.Fatal("oversize value retained")
						}
						if s.field != "" || len(a.BillingShadowExclusion) > 6*shadowCertificateBytes+2 {
							t.Fatal("unbounded retained metadata")
						}
					})
				}
			}
		}
	}
	for _, raw := range []string{
		`{"data":{"model":"billing_shadow_policy","nested":{"billing_shadow_policy":"shadow-v2"}}}`,
		`{"data":{},"other":{"billing_shadow_policy":"shadow-v2"}}`,
		`{"data":{}} {"data":{"billing_shadow_policy":"shadow-v2"}}`,
		`null {"data":{"billing_shadow_policy":"shadow-v2"}}`,
		`{"data":{"billing_shadow_exclusion":"no-policy"}}`,
	} {
		var s shadowCapture
		_, _ = s.Write([]byte(raw))
		var a Authorization
		s.finish(&a)
		if len(a.BillingShadowPolicy) != 0 || len(a.BillingShadowExclusion) != 0 {
			t.Fatal("no-policy capture", raw)
		}
	}
	raw := []byte(`{"DATA":{"billing_shadow_\u0070olicy":"wrong","BILLING_SHADOW_POLICY":"shadow-v2","billing_shadow_exclusion":"A","billing_shadow_binding":null},"data":null}`)
	var s shadowCapture
	_, _ = s.Write(raw)
	var a Authorization
	s.finish(&a)
	if !bytes.Equal(a.BillingShadowPolicy, []byte(`"shadow-v2"`)) || !a.shadowBindingPresent {
		t.Fatal("escaped/duplicate/null presence lost")
	}
}

func TestShadowV2NoPolicyCaptureAllocationClass(t *testing.T) {
	var baseline float64
	for _, count := range []int{1, 100, 1000} {
		raw := []byte(`{"data":{` + strings.Repeat(`"billing_shadow_exclusion":"ignored",`, count) + `"model":"x"}}`)
		allocations := testing.AllocsPerRun(10, func() {
			var s shadowCapture
			_, _ = s.Write(raw)
			var a Authorization
			s.finish(&a)
			if len(a.BillingShadowExclusion) != 0 || len(a.BillingShadowPolicy) != 0 || a.shadowBindingPresent {
				t.Fatal("no-policy retained metadata")
			}
		})
		if count == 1 {
			baseline = allocations
		}
		if allocations != baseline {
			t.Fatalf("no-policy allocation class grew with %d duplicate fields: %g > %g", count, allocations, baseline)
		}
	}
}

// Reviewer witness: last actual entry, isolation, and zero dormant allocations.
func TestShadowV2InvocationFact(t *testing.T) {
	a := &Authorization{EndpointID: "authorized", Provider: "other", shadowSettlement: &shadowAuthorization{exclusion: &shadowExclusion{route: "chat.completions"}}}
	a.RecordShadowInvocation("first", "openai")
	a.RecordShadowInvocation("last", "anthropic")
	body, ok := buildShadowExcluded(a.shadowSettlement.exclusion, Usage{}, "refund", strings.Repeat("a", 40))
	if !ok {
		t.Fatal("no envelope")
	}
	attempt := body["attempt"].(map[string]any)
	if attempt["selected_endpoint"] != "last" || attempt["adapter"] != "anthropic" {
		t.Fatalf("actual invocation lost: %v", attempt)
	}
	other := &Authorization{shadowSettlement: &shadowAuthorization{exclusion: &shadowExclusion{}}}
	body, ok = buildShadowExcluded(other.shadowSettlement.exclusion, Usage{}, "refund", strings.Repeat("a", 40))
	if !ok || body["attempt"].(map[string]any)["selected_endpoint"] != nil {
		t.Fatal("cross authorization leakage")
	}
	for _, auth := range []*Authorization{nil, {}, {shadowSettlement: &shadowAuthorization{}}} {
		if n := testing.AllocsPerRun(100, func() { auth.RecordShadowInvocation("endpoint", "openai") }); n != 0 {
			t.Fatal("dormant recorder allocates", n)
		}
	}
}
