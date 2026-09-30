package speculation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const fixtureDir = "testdata/speculation_v1"
const manifestSHA256 = "efcf82227d5edb22f90482e414ad6c54dba293166a9febd1a976e6a3c234769e"

// Fixture loading retains number types independently of the production parser.
// Out-of-range integers remain json.Number so public APIs refuse them as integer.
func fixtureValue(v any) any {
	switch x := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			f, e := strconv.ParseFloat(string(x), 64)
			if e != nil {
				panic(e)
			}
			return f
		}
		n, e := strconv.ParseInt(string(x), 10, 64)
		if e == nil {
			return n
		}
		return x
	case map[string]any:
		for k, v := range x {
			x[k] = fixtureValue(v)
		}
	case []any:
		for i, v := range x {
			x[i] = fixtureValue(v)
		}
	}
	return v
}
func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(fixtureDir, name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func loadFixture(t testing.TB, name string) map[string]any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(readFixture(t, name)))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		t.Fatal(e)
	}
	return fixtureValue(v).(map[string]any)
}
func m(v any) map[string]any { return v.(map[string]any) }
func s(v any) string {
	if v == nil {
		return ""
	}
	return v.(string)
}
func keys(v any) []TrustedKey {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	var k []TrustedKey
	if e = json.Unmarshal(b, &k); e != nil {
		panic(e)
	}
	return k
}

type harness struct {
	bundle       map[string]any
	keys         []TrustedKey
	wire         []byte
	real, shadow VerifiedGrant
	descriptor   VerifiedDescriptor
}

func rawHarness(t testing.TB) harness {
	t.Helper()
	b := loadFixture(t, "grant-permit-tokens.json")
	h := harness{bundle: b, keys: keys(b["trusted_test_keys"]), wire: bytes.TrimSuffix(readFixture(t, "provider-wire.json"), []byte("\n"))}
	return h
}
func newHarness(t testing.TB) harness {
	t.Helper()
	h := rawHarness(t)
	b := h.bundle
	var e error
	h.real, e = VerifyGrant(b["real_grant_jws"], h.keys, m(b["context"]), b["now"], false)
	if e != nil {
		t.Fatal(e)
	}
	h.shadow, e = VerifyGrant(b["shadow_grant_jws"], h.keys, m(b["context"]), b["now"], true)
	if e != nil {
		t.Fatal(e)
	}
	h.descriptor, e = VerifyDescriptor(b["permit_descriptor_jws"], h.keys, h.real, h.wire, "x1", "n1")
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func (h harness) seedGrant(shadow bool) (VerifiedGrant, error) {
	field := "real_grant_jws"
	if shadow {
		field = "shadow_grant_jws"
	}
	return VerifyGrant(h.bundle[field], h.keys, m(h.bundle["context"]), h.bundle["now"], shadow)
}
func (h harness) seedDescriptor() (VerifiedDescriptor, error) {
	g, e := h.seedGrant(false)
	if e != nil {
		return VerifiedDescriptor{}, e
	}
	return VerifyDescriptor(h.bundle["permit_descriptor_jws"], h.keys, g, h.wire, "x1", "n1")
}
func verdictInput(v any) VerdictInput {
	x := m(v)
	return VerdictInput{s(x["source"]), x["status"], s(x["reason"]), s(x["workspace_id"]), s(x["key_id"]), s(x["rate_scope"])}
}
func (h harness) evaluate(c map[string]any) (any, error) {
	switch c["category"] {
	case "input":
		return SHA256(c["value"])
	case "verdict_extra":
		return ClassifyVerdict(verdictInput(c["input"]))
	case "grant":
		k := h.keys
		if v, ok := c["keys"]; ok {
			k = keys(v)
		}
		_, e := VerifyGrant(c["token"], k, m(c["context"]), c["now"], c["shadow"].(bool))
		return "allowed", e
	case "descriptor":
		g, e := h.seedGrant(c["grant"] == "shadow")
		if e != nil {
			return nil, e
		}
		_, e = VerifyDescriptor(c["token"], h.keys, g, []byte(s(c["wire"])), c["execution"], c["nonce"])
		return "allowed", e
	case "marker":
		d, e := h.seedDescriptor()
		if e != nil {
			return nil, e
		}
		return VerifyAcceptance(m(c["response"]), d, m(c["authorization"]))
	case "cost":
		a := c["args"].([]any)
		return CostCeiling(a[0], a[1], a[2], a[3], a[4])
	case "allowance":
		a := c["args"].([]any)
		return WorkspaceAllowance(a[0], a[1])
	case "renewal":
		previous, e := VerifyGrant(c["previous"], h.keys, m(c["previous_context"]), int64(1700000000), false)
		if e != nil {
			return nil, e
		}
		k := h.keys
		if v, ok := c["candidate_keys"]; ok {
			k = keys(v)
		}
		candidate, e := VerifyGrant(c["candidate"], k, m(c["candidate_context"]), int64(1700000000), c["shadow"].(bool))
		if e != nil {
			return nil, e
		}
		return RenewalVerdict(previous, candidate)
	case "replay":
		g, e := h.seedGrant(false)
		if e != nil {
			return nil, e
		}
		candidate, e := VerifyDescriptor(c["candidate"], h.keys, g, h.wire, c["execution"], c["nonce"])
		if e != nil {
			return nil, e
		}
		d, e := h.seedDescriptor()
		if e != nil {
			return nil, e
		}
		return DescriptorReplay(d, candidate)
	default:
		return nil, fmt.Errorf("unknown category %v", c["category"])
	}
}
func outcomeJSON(t testing.TB, v any) string {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var normalized any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(&normalized); e != nil {
		t.Fatal(e)
	}
	b, e = json.Marshal(normalized)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func TestFixturePins(t *testing.T) {
	if digest(readFixture(t, "manifest.json")) != manifestSHA256 {
		t.Fatal("manifest pin mismatch")
	}
	manifest := loadFixture(t, "manifest.json")
	for name, hash := range m(manifest["files"]) {
		b := readFixture(t, name)
		if digest(b) != hash {
			t.Errorf("fixture pin mismatch: %s", name)
		}
		if !bytes.HasSuffix(b, []byte("\n")) || bytes.HasSuffix(b, []byte("\n\n")) {
			t.Errorf("fixture newline: %s", name)
		}
	}
}
func TestLiterals(t *testing.T) {
	h := rawHarness(t)
	cases := loadFixture(t, "protocol-vectors.json")["cases"].([]any)
	if len(cases) != 434 {
		t.Fatalf("literal count %d", len(cases))
	}
	counts := map[string]int{}
	for _, v := range cases {
		c := m(v)
		counts[s(c["category"])]++
		t.Run(s(c["name"]), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unexpected panic: %v", r)
				}
			}()
			actual, e := h.evaluate(c)
			if e != nil {
				actual = e.Error()
			}
			if a, w := outcomeJSON(t, actual), outcomeJSON(t, c["expected"]); a != w {
				t.Fatalf("expected %s, got %s", w, a)
			}
		})
	}
	names := []string{}
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		t.Logf("%s: %d literals", k, counts[k])
	}
}
func TestVerdicts(t *testing.T) {
	vectors := loadFixture(t, "verdict-vectors.json")["vectors"].([]any)
	if len(vectors) != 24 {
		t.Fatalf("verdict count %d", len(vectors))
	}
	for _, v := range vectors {
		c := m(v)
		t.Run(s(c["name"]), func(t *testing.T) {
			actual, e := ClassifyVerdict(verdictInput(c["input"]))
			if e != nil {
				t.Fatal(e)
			}
			if a, w := outcomeJSON(t, actual), outcomeJSON(t, c["expected"]); a != w {
				t.Fatalf("expected %s, got %s", w, a)
			}
		})
	}
	t.Logf("verdict: %d literals", len(vectors))
}
func TestSeedContract(t *testing.T) {
	h := newHarness(t)
	g, e := h.real.Claims()
	if e != nil {
		t.Fatal(e)
	}
	if !equal(g, h.bundle["grant_claims"]) {
		t.Fatal("grant claims")
	}
	shadow, e := h.shadow.Claims()
	if e != nil || !equal(g, shadow) {
		t.Fatal("shadow claims", e)
	}
	d, e := h.descriptor.Claims()
	if e != nil || !equal(d, h.bundle["permit_descriptor_claims"]) {
		t.Fatal("descriptor claims", e)
	}
	if h.real.StartDeadline() != 1700000028 || h.real.Shadow() || !h.shadow.Shadow() {
		t.Fatal("grant domain/deadline")
	}
	if h.real.Compact() != h.bundle["real_grant_jws"] || h.descriptor.Compact() != h.bundle["permit_descriptor_jws"] {
		t.Fatal("compact bytes")
	}
	hash, e := SHA256(h.wire)
	if e != nil || hash != d["request_sha256"] {
		t.Fatal("wire digest", e)
	}
	g["key_id"] = "mutated"
	fresh, e := h.real.Claims()
	if e != nil || fresh["key_id"] != "k1" {
		t.Fatal("mutable grant", e)
	}
	d["key_id"] = "mutated"
	fresh, e = h.descriptor.Claims()
	if e != nil || fresh["key_id"] != "k1" {
		t.Fatal("mutable descriptor", e)
	}
}
func FuzzTokens(f *testing.F) {
	h := newHarness(f)
	for _, v := range loadFixture(f, "protocol-vectors.json")["cases"].([]any) {
		c := m(v)
		b, e := json.Marshal(c)
		if e != nil {
			f.Fatal(e)
		}
		f.Add(b)
		for _, field := range []string{"token", "previous", "candidate"} {
			if token, ok := c[field].(string); ok {
				f.Add([]byte(token))
				parts := strings.Split(token, ".")
				if len(parts) == 3 {
					for _, p := range parts[:2] {
						raw, e := base64.RawURLEncoding.DecodeString(p)
						if e == nil {
							f.Add(raw)
						}
					}
				}
			}
		}
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(128 + i)
	}
	signer := ed25519.NewKeyFromSeed(seed)
	header := strings.Split(h.real.compact, ".")[0]
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = VerifyGrant(string(raw), h.keys, m(h.bundle["context"]), h.bundle["now"], false)
		_, _ = VerifyDescriptor(string(raw), h.keys, h.real, raw, "x1", "n1")
		// Re-sign arbitrary parser bytes to exercise syntax behind signature validation.
		if len(raw) < 48000 {
			segment := base64.RawURLEncoding.EncodeToString(raw)
			message := header + "." + segment
			token := message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, []byte(message)))
			_, _ = VerifyGrant(token, h.keys, m(h.bundle["context"]), h.bundle["now"], false)
		}
	})
}
