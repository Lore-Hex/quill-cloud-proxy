package speculation

import (
	"encoding/json"
	"math"
	"runtime"
	"strings"
	"testing"
)

func TestEncodedBudget(t *testing.T) {
	values := []any{nil, true, false, int(123), int64(-9223372036854775808), 0.25, "", "雪🙂\u2028\u2029<>&\x00\n\r\t\b\f\"\\", []any{}, map[string]any{}, []any{true, nil, "x"}, map[string]any{"nested": []any{int64(4), "<"}}}
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		b := encodedBudget{8192}
		if r := b.value(value, 0); r != ReasonEligible || 8192-b.remaining < len(raw) {
			t.Fatalf("%#v: %s, %d < %d", value, r, 8192-b.remaining, len(raw))
		}
		b.remaining = len(raw) - 1
		if r := b.value(value, 0); r != ReasonInputBound {
			t.Fatalf("accepted over budget: %#v (%s)", value, r)
		}
	}
	for _, v := range []any{math.NaN(), math.Inf(1), make(chan int), string([]byte{255})} {
		b := encodedBudget{8192}
		if r := b.value(v, 0); r != ReasonPayload {
			t.Fatal(r)
		}
	}
	for _, v := range []any{strings.Repeat("<", 2000), make([]any, 8192), map[string]any{strings.Repeat("x", 8192): 0}, map[string]any{"x": strings.Repeat("x", 8192)}} {
		b := encodedBudget{8192}
		if r := b.value(v, 0); r != ReasonInputBound {
			t.Fatal(r)
		}
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	b := encodedBudget{8192}
	if r := b.value(cycle, 0); r != ReasonInputBound {
		t.Fatal(r)
	}
	for _, limit := range []int{0, 1, 2, 3, 4, 5} {
		for _, v := range []any{[]any{false}, map[string]any{"x": true}} {
			b := encodedBudget{limit}
			if r := b.value(v, 0); r != ReasonInputBound {
				t.Fatal(limit, r)
			}
		}
	}
	for _, prefix := range [][]string{make([]string, 300), {strings.Repeat("<", 2000)}, {string([]byte{255})}} {
		if r := precheckChat(nil, prefix, "", 8192); r == ReasonEligible {
			t.Fatal("accepted prefix")
		}
	}
	if r := precheckChat(nil, []string{"a", "b"}, "", 60); r != ReasonInputBound {
		t.Fatal(r)
	}
}

func TestCacheScopeBudget(t *testing.T) {
	for _, limit := range []int{1, 22} {
		if r := precheckChat(nil, nil, "scope", limit); r != ReasonInputBound {
			t.Fatal(r)
		}
	}
}

func TestOversizedPayloadAllocations(t *testing.T) {
	for _, shape := range []string{"text", "messages", "nested", "escaped"} {
		t.Run(shape, func(t *testing.T) {
			c := eligibleCase(t)
			switch shape {
			case "text":
				m(c.req.Body["messages"].([]any)[0])["content"] = strings.Repeat("<", 9<<20)
			case "messages":
				c.req.Body["messages"] = make([]any, 1<<20)
			case "nested":
				c.req.Body["logit_bias"] = map[string]any{"x": make([]any, 1<<20)}
			case "escaped":
				m(c.req.Body["messages"].([]any)[0])["content"] = strings.Repeat("<", 8000)
			}
			run := func() {
				p, r := PreparePayload(c.grant.grant, c.local.Certificates, c.req)
				if r != ReasonInputBound || len(p.Bytes) != 0 {
					t.Fatalf("%s %d", r, len(p.Bytes))
				}
			}
			allocs := testing.AllocsPerRun(5, run)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := 0; i < 5; i++ {
				run()
			}
			runtime.ReadMemStats(&after)
			allocated := (after.TotalAlloc - before.TotalAlloc) / 5
			t.Logf("%s: %.0f allocations/op, %d bytes/op", shape, allocs, allocated)
			if allocated > 128<<10 || allocs > 1000 {
				t.Fatalf("work exceeded fixed budget: %.0f allocations, %d bytes", allocs, allocated)
			}
		})
	}
}

func BenchmarkOversizedPayload(b *testing.B) {
	c := eligibleCase(b)
	m(c.req.Body["messages"].([]any)[0])["content"] = strings.Repeat("<", 9<<20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, r := PreparePayload(c.grant.grant, c.local.Certificates, c.req); r != ReasonInputBound {
			b.Fatal(r)
		}
	}
}
