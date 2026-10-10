package billingv1

import (
	"bytes"
	"errors"
	"testing"
)

// These three inputs reproduced the Go/Python differences in Astra's review.
// Expected canonical bytes/hash are pinned by the tightened Python fixture.
func TestEncodingDifferentialRegressions(t *testing.T) {
	t.Run("del", func(t *testing.T) {
		value, err := ParseEligibility([]byte(`{"usage_type":"\u007f"}`))
		if err != nil {
			t.Fatal(err)
		}
		c := fixtureNamed(t, "eligibility_canonical_del")
		raw, err := CanonicalBytes(value)
		if err != nil || c.ExpectedCanonicalASCII == nil || string(raw) != *c.ExpectedCanonicalASCII {
			t.Fatalf("canonical DEL: %q (%v)", raw, err)
		}
		checkHash(t, value, c.ExpectedHash)
	})
	t.Run("lone_surrogate", func(t *testing.T) {
		_, err := ParseEligibility([]byte(`{"usage_type":"\ud800"}`))
		requireWireError(t, err, "invalid_string")
	})
	t.Run("snapshot_bom", func(t *testing.T) {
		raw := fixtureNamed(t, "openai_cache").Snapshot
		if _, err := ParseSnapshot(raw); err != nil {
			t.Fatal(err)
		}
		_, err := ParseSnapshot(append([]byte{0xef, 0xbb, 0xbf}, raw...))
		requireWireError(t, err, "invalid_encoding")
	})
}

func requireWireError(t *testing.T, err error, code string) {
	t.Helper()
	var wire *Error
	if !errors.As(err, &wire) || wire.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestStringEscapeBoundaries(t *testing.T) {
	for _, value := range []string{
		`\ud800`, `\udbff`, `\udc00`, `\udfff`,
		`\ud800\ud800`, `\ud800x\udc00`, `\ud800\\udc00`,
		`\udc00\ud800`, `\ud800\udc00\udfff`,
	} {
		t.Run(value, func(t *testing.T) {
			for _, raw := range []string{
				`{"usage_type":"` + value + `"}`,
				`{"unknown":[{"` + value + `":true}]}`,
				`{"unknown":[{"value":"` + value + `"}]}`,
			} {
				_, err := ParseEligibility([]byte(raw))
				requireWireError(t, err, "invalid_string")
			}
		})
	}
	for _, value := range []string{
		`\ud800\udc00`, `\uDBFF\uDFFF`, `\ud7ff`, `\ue000`,
		`\\ud800`, `\\\"ud800`, `\ufffd`, `😀`, `\ufeff`, `\u0000`,
	} {
		t.Run("valid_"+value, func(t *testing.T) {
			if _, err := ParseEligibility([]byte(`{"usage_type":"` + value + `"}`)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAllParseEntryPointsRejectWireErrors(t *testing.T) {
	parsers := map[string]func([]byte) error{
		"snapshot":    func(b []byte) error { _, err := ParseSnapshot(b); return err },
		"eligibility": func(b []byte) error { _, err := ParseEligibility(b); return err },
		"raw_usage":   func(b []byte) error { _, err := ParseRawUsage(b); return err },
		"envelope":    func(b []byte) error { _, err := ParseEnvelope(b); return err },
		"acceptance":  func(b []byte) error { _, err := ParseAcceptance(b); return err },
		"endpoint":    func(b []byte) error { _, err := ParseEndpoint(b); return err },
	}
	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			for _, raw := range [][]byte{
				append([]byte{0xef, 0xbb, 0xbf}, []byte(`{}`)...),
				{'{', 0, '}', 0}, {0, '{', 0, '}'},
				{'{', 0, 0, 0, '}', 0, 0, 0}, {0, 0, 0, '{', 0, 0, 0, '}'},
				[]byte("{\"unknown\":\"\xff\"}"), []byte("{\"unknown\":\"\xed\xa0\x80\"}"),
				append([]byte(`{}`), 0),
			} {
				requireWireError(t, parse(raw), "invalid_encoding")
			}
			for _, raw := range []string{`{"unknown":[{"value":"\ud800"}]}`, `{"unknown":[{"\udfff":true}]}`} {
				requireWireError(t, parse([]byte(raw)), "invalid_string")
			}
		})
	}
}

func TestCanonicalAllC0Controls(t *testing.T) {
	value := DefaultEligibility()
	for r := byte(0); r < 32; r++ {
		value.UsageType += string(r)
	}
	raw, err := CanonicalBytes(value)
	want := `"usage_type":"Credits\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`
	if err != nil || !bytes.Contains(raw, []byte(want)) {
		t.Fatalf("canonical C0: %s (%v)", raw, err)
	}
}
