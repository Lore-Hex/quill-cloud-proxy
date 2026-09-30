package speculation

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"testing"
	"time"
)

func TestReviewAcceptance(t *testing.T) {
	h := newHarness(t)
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile("testdata/review/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	decode := func(raw []byte) map[string]any {
		t.Helper()
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return m(fixtureValue(v))
	}
	cases := []map[string]any{decode(read("acceptance-depth-128.json"))}
	d := json.NewDecoder(bytes.NewReader(read("divergences.jsonl")))
	for {
		var raw json.RawMessage
		if err := d.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		row := decode(raw)
		c := m(row["case"])
		if c["expected"] != row["python"] {
			t.Fatal("review oracle mismatch")
		}
		cases = append(cases, c)
	}
	if len(cases) != 17 {
		t.Fatalf("review case count: %d", len(cases))
	}
	for _, c := range cases {
		t.Run(s(c["name"]), func(t *testing.T) {
			// Every review input and its combined deep/mismatch variant must give
			// the Python outcome on every iteration, regardless of Go map order.
			for _, mismatch := range []bool{false, true} {
				expected := s(c["expected"])
				if mismatch {
					m(m(c["response"])["authorization"])["authorization_id"] = "different"
					expected = "authorization"
				}
				for i := 0; i < 1000; i++ {
					actual, err := VerifyAcceptance(m(c["response"]), h.descriptor, m(c["authorization"]))
					if err != nil {
						actual = err.Error()
					}
					if actual != expected {
						t.Fatalf("iteration %d mismatch=%v: want %s, got %s", i, mismatch, expected, actual)
					}
				}
			}
		})
	}
}

func TestEqualValues(t *testing.T) {
	mapCycle := map[string]any{}
	mapCycle["self"] = mapCycle
	otherCycle := map[string]any{}
	otherCycle["self"] = otherCycle
	sliceCycle := []any{nil}
	sliceCycle[0] = sliceCycle
	// Reusing the starting pointer with another length is a distinct slice view.
	sharedMap := map[string]any{"x": int64(1)}
	left := []any{int64(0), int64(1)}
	right := []any{int64(0), int64(2)}
	cases := []struct {
		name string
		a, b any
		want bool
	}{
		{"nil", nil, nil, true},
		{"nil_type", nil, false, false},
		{"bool", true, true, true},
		{"bool_type", true, int64(1), false},
		{"string_type", "1", int64(1), false},
		{"int", int(1), int(1), true},
		{"int64_int", int64(1), int(1), true},
		{"int_int64", int(1), int64(1), true},
		{"int_float", int64(1), float64(1), false},
		{"float", 1.5, 1.5, true},
		{"float_type", 1.0, int64(1), false},
		{"nan", math.NaN(), math.NaN(), false},
		{"unsupported", json.Number("1"), json.Number("1"), false},
		{"unsupported_nested", map[string]any{"x": make(chan int)}, map[string]any{"x": nil}, false},
		{"map_type", map[string]any{}, []any{}, false},
		{"map_length", map[string]any{}, map[string]any{"x": nil}, false},
		{"map_keys", map[string]any{"x": nil}, map[string]any{"y": nil}, false},
		{"slice_type", []any{}, map[string]any{}, false},
		{"slice_length", []any{}, []any{nil}, false},
		{"nil_map", map[string]any(nil), map[string]any{}, true},
		{"nil_slice", []any(nil), []any{}, true},
		{"map_cycle", mapCycle, mapCycle, false},
		{"separate_cycles", mapCycle, otherCycle, false},
		{"slice_cycle", sliceCycle, sliceCycle, false},
		{"cycle_vs_finite", sliceCycle, []any{[]any{}}, false},
		{"map_right_identity", []any{sharedMap, sharedMap}, []any{sharedMap, map[string]any{"x": int64(2)}}, false},
		{"slice_right_identity", []any{left, left}, []any{left, right}, false},
		{"slice_views", []any{left[:1], left}, []any{right[:1], right}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := equal(c.a, c.b); got != c.want {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}

func TestEqualDeep(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("equality must not panic: %v", r)
		}
	}()
	var a, b, different any = int64(0), int64(0), int64(1)
	for i := 0; i < 10000; i++ {
		a, b, different = []any{a}, []any{b}, []any{different}
	}
	if !equal(a, b) || equal(a, different) {
		t.Fatal("deep equality")
	}
}

func TestEqualSharedDAG(t *testing.T) {
	h := newHarness(t)
	for _, maps := range []bool{false, true} {
		var a, b any = int64(0), int64(0)
		for i := 0; i < 30; i++ {
			if maps {
				a, b = map[string]any{"a": a, "b": a}, map[string]any{"a": b, "b": b}
			} else {
				a, b = []any{a, a}, []any{b, b}
			}
		}
		auth := m(h.bundle["authorization"])
		auth["extra"] = a
		other := make(map[string]any, len(auth))
		for k, v := range auth {
			other[k] = v
		}
		other["extra"] = b
		// A timeout makes loss of memoization fail promptly even at depth 30.
		result := make(chan bool, 1)
		start := time.Now()
		go func() {
			same, err1 := VerifyAcceptance(map[string]any{"authorization": auth}, h.descriptor, auth)
			independent, err2 := VerifyAcceptance(map[string]any{"authorization": other}, h.descriptor, auth)
			result <- same == "ordinary" && independent == "ordinary" && err1 == nil && err2 == nil
		}()
		select {
		case ok := <-result:
			if !ok {
				t.Fatal("shared subtree equality")
			}
			t.Logf("depth-30 DAG maps=%v: %s", maps, time.Since(start))
		case <-time.After(time.Second):
			t.Fatal("shared subtree comparison exceeded one second")
		}
	}
}
