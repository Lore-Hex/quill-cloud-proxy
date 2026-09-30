package speculation

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	emptyMap, emptySlice := map[string]any{}, make([]any, 0, 1)
	left := []any{int64(0), int64(1)}
	right := []any{int64(0), int64(2)}
	cases := []struct {
		name string
		a, b any
		want bool
	}{
		{"shared_map_left", []any{sharedMap, sharedMap}, []any{map[string]any{"x": int64(1)}, map[string]any{"x": int64(1)}}, false},
		{"shared_map_right", []any{map[string]any{"x": int64(1)}, map[string]any{"x": int64(1)}}, []any{sharedMap, sharedMap}, false},
		{"shared_slice_left", []any{left, left}, []any{[]any{int64(0), int64(1)}, []any{int64(0), int64(1)}}, false},
		{"shared_slice_right", []any{[]any{int64(0), int64(1)}, []any{int64(0), int64(1)}}, []any{left, left}, false},
		{"independent_views", []any{left[:1], left}, []any{[]any{int64(0)}, []any{int64(0), int64(1)}}, true},
		{"empty_containers", []any{[]any{}, []any{}, map[string]any{}, map[string]any{}, map[string]any(nil), map[string]any(nil)}, []any{[]any{}, []any(nil), map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}}, true},
		{"shared_empty_map", []any{emptyMap, emptyMap}, []any{map[string]any{}, map[string]any{}}, false},
		{"shared_empty_slice", []any{emptySlice, emptySlice}, []any{[]any{}, []any{}}, false},
		{"shared_empty_slice_right", []any{[]any{}, []any{}}, []any{emptySlice, emptySlice}, false},
		{"same_tree", []any{sharedMap, left}, []any{sharedMap, left}, true},
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
			if got := equalWithin(t, c.a, c.b, time.Second); got != c.want {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}

// The time bound also kills missing-identity mutations without hanging a run.
func equalWithin(t *testing.T, a, b any, limit time.Duration) bool {
	t.Helper()
	type outcome struct {
		value      bool
		panicValue any
	}
	result := make(chan outcome, 1)
	start := time.Now()
	go func() {
		var got outcome
		defer func() { got.panicValue = recover(); result <- got }()
		got.value = equal(a, b)
	}()
	select {
	case got := <-result:
		if got.panicValue != nil {
			t.Fatalf("comparison panicked: %v", got.panicValue)
		}
		t.Logf("comparison: %s", time.Since(start))
		return got.value
	case <-time.After(limit):
		t.Fatalf("comparison exceeded %s", limit)
		return false
	}
}

func TestEqualDeep(t *testing.T) {
	for _, depth := range []int{10000, 100000} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			var a, b, different any = int64(0), int64(0), int64(1)
			for i := 0; i < depth; i++ {
				if i%2 == 0 {
					a, b, different = []any{a}, []any{b}, []any{different}
				} else {
					a, b, different = map[string]any{"x": a}, map[string]any{"x": b}, map[string]any{"x": different}
				}
			}
			if !equalWithin(t, a, b, 10*time.Second) || equalWithin(t, a, different, 10*time.Second) {
				t.Fatal("deep equality")
			}
		})
	}
}

func TestEqualWide(t *testing.T) {
	for _, size := range []int{100000, 1000000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// Root plus size-1 scalar leaves: exactly size nodes per tree.
			a, b := make([]any, size-1), make([]any, size-1)
			for i := range a {
				a[i], b[i] = i, i
			}
			if !equalWithin(t, a, b, 10*time.Second) {
				t.Fatal("wide tree equality")
			}
			b[len(b)-1] = -1
			if equalWithin(t, a, b, 10*time.Second) {
				t.Fatal("wide tree mismatch")
			}
		})
	}
	// Also exercise wide objects and the identity sets, not just scalar leaves.
	t.Run("object_containers_100000", func(t *testing.T) {
		a, b := map[string]any{}, map[string]any{}
		for i := 0; i < 100000; i++ {
			k := fmt.Sprint(i)
			a[k], b[k] = []any{i}, []any{i}
		}
		if !equalWithin(t, a, b, 10*time.Second) {
			t.Fatal("wide object equality")
		}
	})
}

func TestEqualMemberOrder(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("comparison panicked: %v", r)
		}
	}()
	a, b := map[string]any{}, map[string]any{}
	for i := 0; i < 64; i++ {
		a[fmt.Sprint(i)] = map[string]any{"a": i, "b": []any{i, true}}
		j := 63 - i
		b[fmt.Sprint(j)] = map[string]any{"b": []any{j, true}, "a": j}
	}
	for i := 0; i < 100; i++ {
		if !equal(a, b) {
			t.Fatal("member order changed equality")
		}
	}
}

func TestEqualRings(t *testing.T) {
	ring := func(size int) []any {
		nodes := make([][]any, size)
		for i := range nodes {
			nodes[i] = []any{nil}
		}
		for i := range nodes {
			nodes[i][0] = nodes[(i+1)%size]
		}
		return nodes[0]
	}
	for _, size := range []int{800, 801} {
		t.Run(fmt.Sprintf("800_vs_%d", size), func(t *testing.T) {
			if equalWithin(t, ring(800), ring(size), time.Second) {
				t.Fatal("rings are not JSON trees")
			}
		})
	}
}

func TestEqualCross(t *testing.T) {
	// Exact cross(10) graph from the combined review reproduction.
	const k = 10
	var tree, left func(int) any
	tree = func(n int) any {
		if n == 0 {
			return 0
		}
		return []any{tree(n - 1), tree(n - 1)}
	}
	left = func(n int) any {
		if n > 0 {
			return []any{left(n - 1), left(n - 1)}
		}
		var x any = 0
		for i := 0; i < k; i++ {
			x = []any{x, x}
		}
		return x
	}
	a, b := left(k), tree(k)
	for i := 0; i < k; i++ {
		b = []any{b, b}
	}
	if equalWithin(t, a, b, time.Second) || equalWithin(t, b, a, time.Second) {
		t.Fatal("cross-shared DAGs are not JSON trees")
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
		// A timeout bounds regressions that expand a shared graph into a tree.
		result := make(chan bool, 1)
		start := time.Now()
		go func() {
			same, err1 := VerifyAcceptance(map[string]any{"authorization": auth}, h.descriptor, auth)
			independent, err2 := VerifyAcceptance(map[string]any{"authorization": other}, h.descriptor, auth)
			result <- same == "" && independent == "" && err1 == ProtocolError("authorization") && err2 == ProtocolError("authorization")
		}()
		select {
		case ok := <-result:
			if !ok {
				t.Fatal("shared subtrees must refuse authorization")
			}
			t.Logf("depth-30 DAG maps=%v: %s", maps, time.Since(start))
		case <-time.After(time.Second):
			t.Fatal("shared subtree comparison exceeded one second")
		}
	}
}
