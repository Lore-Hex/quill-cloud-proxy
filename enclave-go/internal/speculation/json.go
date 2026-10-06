package speculation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// ProtocolError is a stable v1 refusal code.
type ProtocolError string

func (e ProtocolError) Error() string { return string(e) }

// Internally, refusal unwinds ordered validation. Only protocol refusals are
// recovered: implementation panics must remain visible to tests and fuzzing.
func refusal(err *error) {
	if r := recover(); r != nil {
		if e, ok := r.(ProtocolError); ok {
			*err = e
		} else {
			panic(r)
		}
	}
}
func require(ok bool, code string) {
	if !ok {
		panic(ProtocolError(code))
	}
}

func integer(v any) int64 {
	var n int64
	switch x := v.(type) {
	case int64:
		n = x
	case int:
		n = int64(x)
	default:
		panic(ProtocolError("integer"))
	}
	require(n >= 0, "integer")
	return n
}
func stringValue(v any) string {
	s, ok := v.(string)
	require(ok && len(s) > 0, "string")
	for i := 0; i < len(s); i++ {
		require(s[i] >= 0x20 && s[i] <= 0x7e && !strings.ContainsRune("\\\"<>&", rune(s[i])), "string")
	}
	return s
}
func hashValue(v any) {
	s, ok := v.(string)
	require(ok && len(s) == 64, "hash")
	for _, c := range s {
		require(c >= '0' && c <= '9' || c >= 'a' && c <= 'f', "hash")
	}
}
func object(v any, ss, ns, nested string) map[string]any {
	m, ok := v.(map[string]any)
	require(ok, "fields")
	fields := strings.Fields(ss + " " + ns + " " + nested)
	require(len(m) == len(fields), "fields")
	for _, f := range fields {
		_, ok = m[f]
		require(ok, "fields")
	}
	for _, f := range strings.Fields(ss) {
		stringValue(m[f])
	}
	for _, f := range strings.Fields(ns) {
		integer(m[f])
	}
	return m
}
func byteRule(raw []byte) {
	for _, b := range raw {
		require(b >= 0x20 && b <= 0x7e && b != 0x5c, "json")
	}
}
func depthCheck(raw []byte) {
	depth := 0
	quoted := false
	for _, b := range raw {
		if b == '"' {
			quoted = !quoted
		}
		if !quoted {
			switch b {
			case '[', '{':
				depth++
				require(depth <= 16, "json")
			case ']', '}':
				depth--
			}
		}
	}
}

// encoding/json deliberately excludes the three Python JSON constants. Replace
// complete, unquoted constant tokens with a numeric placeholder, remembering its
// end offset. Malformed surrounding syntax still goes through Decoder.Token.
func constants(raw []byte) ([]byte, map[int64]string) {
	out := make([]byte, 0, len(raw))
	ends := map[int64]string{}
	quoted := false
	for i := 0; i < len(raw); {
		if raw[i] == '"' {
			quoted = !quoted
		}
		found := ""
		if !quoted && (i == 0 || strings.ContainsRune(" [{:,", rune(raw[i-1]))) {
			for _, s := range []string{"NaN", "Infinity", "-Infinity"} {
				if bytes.HasPrefix(raw[i:], []byte(s)) {
					end := i + len(s)
					if end == len(raw) || strings.ContainsRune(" ,]}:", rune(raw[end])) {
						found = s
						break
					}
				}
			}
		}
		if found != "" {
			out = append(out, '0')
			ends[int64(len(out))] = found
			i += len(found)
		} else {
			out = append(out, raw[i])
			i++
		}
	}
	return out, ends
}

type jsonPass struct {
	dec        *json.Decoder
	duplicates bool
	numbers    []json.Number
	constants  map[int64]string
}

func (p *jsonPass) token() any { t, e := p.dec.Token(); require(e == nil, "json"); return t }
func (p *jsonPass) value() any {
	t := p.token()
	if d, ok := t.(json.Delim); ok {
		switch d {
		case '{':
			m := map[string]any{}
			for p.dec.More() {
				k, ok := p.token().(string)
				require(ok, "json")
				v := p.value()
				if _, exists := m[k]; exists {
					p.duplicates = true
				}
				m[k] = v
			}
			require(p.token() == json.Delim('}'), "json")
			return m
		case '[':
			a := []any{}
			for p.dec.More() {
				a = append(a, p.value())
			}
			require(p.token() == json.Delim(']'), "json")
			return a
		default:
			panic(ProtocolError("json"))
		}
	}
	if n, ok := t.(json.Number); ok {
		if c, exists := p.constants[p.dec.InputOffset()]; exists {
			n = json.Number(c)
		}
		p.numbers = append(p.numbers, n)
		return n
	}
	return t
}
func rawInteger(n json.Number) int64 {
	s := string(n)
	digits := strings.TrimPrefix(s, "-")
	require(len(digits) <= 19 && !strings.ContainsAny(s, ".eE") && digits != "", "integer")
	v, e := strconv.ParseInt(s, 10, 64)
	require(e == nil && v >= 0, "integer")
	return v
}
func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		return rawInteger(x)
	case map[string]any:
		for k, v := range x {
			x[k] = normalize(v)
		}
	case []any:
		for i, v := range x {
			x[i] = normalize(v)
		}
	}
	return v
}
func parseJSON(raw []byte) any {
	byteRule(raw)
	depthCheck(raw)
	replaced, cs := constants(raw)
	d := json.NewDecoder(bytes.NewReader(replaced))
	d.UseNumber()
	p := jsonPass{dec: d, constants: cs}
	v := p.value()
	_, e := d.Token()
	require(e == io.EOF, "json")
	require(!p.duplicates, "duplicate_key")
	for _, n := range p.numbers {
		rawInteger(n)
	}
	return normalize(v)
}
func canonical(v any) []byte           { b, e := json.Marshal(v); require(e == nil, "input"); return b }
func checkCanonical(v any, raw []byte) { require(bytes.Equal(raw, canonical(v)), "canonical_payload") }
func b64decode(value any) []byte {
	s, ok := value.(string)
	require(ok && s != "", "base64")
	for _, c := range s {
		require(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-', "base64")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	require(e == nil && base64.RawURLEncoding.EncodeToString(b) == s, "base64")
	return b
}

// equal compares caller JSON trees without coercing booleans, integers or floats.
// Each input has its own identity set: sharing or a cycle in either is unequal.
// A single iterative walk with map key lookup takes O(size(a) + size(b)) time
// and space, without a depth limit or a comparison-specific error.
// Pointer identities retain containers. Slice length distinguishes views of the
// same backing array. Empty containers carry no identity (normative, matching the
// Python reference): they have no children, and Go's decoder gives every empty
// array one shared address, so a shared empty object or array compares by value.
func equal(a, b any) bool {
	type identity struct {
		pointer unsafe.Pointer
		length  int
		array   bool
	}
	type frame struct{ a, b any }
	stack := []frame{{a: a, b: b}}
	leftSeen, rightSeen := map[identity]bool{}, map[identity]bool{}
	visit := func(seen map[identity]bool, id identity) bool {
		if id.pointer == nil {
			return true
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		return true
	}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch x := f.a.(type) {
		case map[string]any:
			y, ok := f.b.(map[string]any)
			if !ok || len(x) != len(y) {
				return false
			}
			if len(x) > 0 && (!visit(leftSeen, identity{pointer: reflect.ValueOf(x).UnsafePointer()}) ||
				!visit(rightSeen, identity{pointer: reflect.ValueOf(y).UnsafePointer()})) {
				return false
			}
			// Equal lengths and membership establish the complete key set.
			// Matching by key avoids sorting and ignores map iteration order.
			for k := range x {
				if _, ok := y[k]; !ok {
					return false
				}
				stack = append(stack, frame{a: x[k], b: y[k]})
			}
		case []any:
			y, ok := f.b.([]any)
			if !ok || len(x) != len(y) {
				return false
			}
			if len(x) > 0 && !visit(leftSeen, identity{pointer: reflect.ValueOf(x).UnsafePointer(), length: len(x), array: true}) {
				return false
			}
			if len(y) > 0 && !visit(rightSeen, identity{pointer: reflect.ValueOf(y).UnsafePointer(), length: len(y), array: true}) {
				return false
			}
			for i := len(x) - 1; i >= 0; i-- {
				stack = append(stack, frame{a: x[i], b: y[i]})
			}
		default:
			if !equalScalar(f.a, f.b) {
				return false
			}
		}
	}
	return true
}

func equalScalar(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case int:
		// int and int64 are the two supported representations of a JSON integer.
		return equalScalar(int64(x), b)
	case int64:
		switch y := b.(type) {
		case int:
			return x == int64(y)
		case int64:
			return x == y
		}
		return false
	case float64:
		y, ok := b.(float64)
		return ok && x == y && !math.IsNaN(x)
	default:
		return false
	}
}
