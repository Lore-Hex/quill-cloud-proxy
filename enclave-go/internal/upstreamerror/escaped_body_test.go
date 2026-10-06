package upstreamerror

import (
	"context"
	"strings"
	"testing"
)

func TestUndecodableBodyNormalizesEscapesBeforeRedaction(t *testing.T) {
	for _, tc := range []struct{ name, secret, escaped string }{
		{"unicode", "provider-owned-secret", `\u0070\u0072\u006f\u0076\u0069\u0064\u0065\u0072\u002d\u006f\u0077\u006e\u0065\u0064\u002d\u0073\u0065\u0063\u0072\u0065\u0074`},
		{"mixed", "provider-owned-secret", `pro\u0076ider-owned-\u0073ecret`},
		{"surrogate pair", "private-🔐-secret", `private-\ud83d\udd10-secret`},
		{"short escapes", "private-\"\\/\b\f\n\r\t-secret", `private-\"\\\/\b\f\n\r\t-secret`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, redact := WithCredentialRedaction(context.Background(), tc.secret)
			body := `{"message":"rejected ` + tc.escaped + `","padding":"` + strings.Repeat("x", 5000)
			d := Parse(redact(&Error{Status: 400, Body: body[:4096]}))
			want := bounded(`{"message":"rejected ***","padding":"` + strings.Repeat("x", 5000))
			if d.Message != want || d.Raw != want {
				t.Fatalf("escaped credential retained: %+v", d)
			}
		})
	}
	for _, body := range []string{
		`{"X-\u0041pi-Key":"unknown-\u0073ecret","padding":`,
		`{"message":"Bearer unknown-\u0073ecret sk-abc\u0064ef","padding":`,
		`{} {"X-\u0041pi-Key":"unknown-\u0073ecret","padding":`,
	} {
		d := Parse(&Error{Status: 400, Body: body})
		if strings.Contains(d.Raw, `\u`) || strings.Contains(d.Raw, "secret") || strings.Contains(d.Raw, "abcdef") || !strings.Contains(d.Raw, "***") {
			t.Fatalf("credential name/token shape not redacted: %+v", d)
		}
	}
}

// Decoding keeps only the last duplicate key, so a credential in an earlier
// duplicate must not survive by returning the raw body unchanged.
func TestDecodableBodyRedactsDiscardedDuplicateKeys(t *testing.T) {
	const secret = "provider-owned-secret"
	_, redact := WithCredentialRedaction(context.Background(), secret)
	escapedS := string(rune(92)) + "u0073" // the JSON escape for "s"
	for _, body := range []string{
		`{"message":"rejected provider-owned-secret","message":"rejected"}`,
		`{"message":"rejected provider-owned-` + escapedS + `ecret","message":"rejected"}`,
		`{"error":{"message":"Bearer sk-abcdef123456","message":"denied"}}`,
	} {
		d := Parse(redact(&Error{Status: 400, Body: body}))
		if strings.Contains(d.Raw, "secret") || strings.Contains(d.Raw, escapedS) || strings.Contains(d.Raw, "sk-abcdef") {
			t.Fatalf("duplicate key leaked a credential: %+v", d)
		}
	}
	// Positive controls: an unchanged body keeps its exact bytes, and a plain
	// credential value is still scrubbed.
	const clean = `{"error": {"message": "model not found", "code": 404}}`
	if d := Parse(redact(&Error{Status: 404, Body: clean})); d.Raw != clean {
		t.Fatalf("clean body changed: %q", d.Raw)
	}
	if d := Parse(redact(&Error{Status: 400, Body: `{"message":"key provider-owned-secret rejected"}`})); strings.Contains(d.Raw, secret) {
		t.Fatalf("plain credential leaked: %+v", d)
	}
}
