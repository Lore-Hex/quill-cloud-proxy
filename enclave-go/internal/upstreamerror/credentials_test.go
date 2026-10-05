package upstreamerror

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCredentialRedactionByValueAndName(t *testing.T) {
	const key = "provider-owned-secret"
	for _, payload := range []string{
		`{"error":{"message":"provider-owned-secret","code":"provider-owned-secret","param":"provider-owned-secret","type":"provider-owned-secret"}}`,
		`{"error":{"message":"provider-owned-\u0073ecret"},"provider-owned-secret":"value","headers":{"X-Api-Key":"unknown-key","X-Goog-Api-Key":"unknown-key","api-key":"unknown-key","Authorization":"unknown-key"}}`,
		`{"error":{"code":12345678,"param":12345678},"headers":{"api-key":"unknown-key"}}`,
		"rejected provider-owned-secret 12345678; x-api-key: unknown-key; x-goog-api-key=unknown-key; Authorization: Bearer unknown-key",
	} {
		ctx, redact := WithCredentialRedaction(context.Background(), key)
		RecordCredential(ctx, "Bearer 12345678")
		for _, err := range []error{&Error{Status: 400, Body: payload}, fmt.Errorf("llm/provider: http 400: %s", payload)} {
			redacted := redact(err)
			_, retained := redacted.(interface{ UpstreamResponse() (int, string) }).UpstreamResponse()
			fields, _ := json.Marshal(Parse(redacted))
			for _, secret := range []string{key, "12345678", "unknown-key"} {
				if strings.Contains(string(fields), secret) || strings.Contains(retained, secret) {
					t.Fatalf("credential retained: %s / %s", retained, fields)
				}
			}
		}
	}
}

func TestCredentialRedactionRemovesUnterminatedFields(t *testing.T) {
	for _, body := range []string{
		`{"x-api-key":"unknown-credential`,
		`{"x-\u0061pi-key":"unknown-\u0063redential`,
		`{"password":"unknown\ncredential`,
	} {
		// No registered value: credential field names must suffice on their own.
		_, redact := WithCredentialRedaction(t.Context())
		got := redact(&Error{Status: 400, Body: body}).(*Error).Body
		want := `{"x-api-key":"***`
		if strings.Contains(body, "password") {
			want = `{"password":"***`
		}
		if got != want {
			t.Errorf("unterminated field: got %q, want %q", got, want)
		}
	}
}

func TestCredentialRedactionRemovesTrailingSecretPrefixes(t *testing.T) {
	const secret = "provider-owned-secret"
	for _, tc := range []struct{ name, secret, body, want string }{
		{"cut by one character", secret, `{"message":"rejected provider-owned-secre`, `{"message":"rejected ***`},
		{"cut mid value", secret, `{"message":"rejected provider-own`, `{"message":"rejected ***`},
		{"eight characters", secret, `{"message":"rejected provider`, `{"message":"rejected ***`},
		{"escaped prefix", secret, `{"message":"rejected pro\u0076ider-\u006fwn`, `{"message":"rejected ***`},
		{"exact then truncated", secret, `{"message":"provider-owned-secret then provider-own`, `{"message":"*** then ***`},
		{"escaped special characters", "provider/\"\\secret", `{"message":"rejected provider\/\"\\sec`, `{"message":"rejected ***`},
		{"ordinary short prefix", secret, `ordinary text about provide`, `ordinary text about provide`},
		{"non trailing prefix", secret, `ordinary provider-owned text`, `ordinary provider-owned text`},
		{"whole short secret", "abc", `{"message":"rejected abc`, `{"message":"rejected ***`},
		{"partial short secret", "abc", `ordinary ab`, `ordinary ab`},
		{"unicode eight characters", "🔐abcdefg-secret", `{"message":"rejected \ud83d\udd10abcdefg`, `{"message":"rejected ***`},
		{"unicode short prefix", "🔐abcdefg-secret", `ordinary 🔐abcd`, `ordinary 🔐abcd`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, redact := WithCredentialRedaction(t.Context())
			RecordCredential(ctx, tc.secret)
			got := redact(&Error{Status: 400, Body: tc.body}).(*Error).Body
			if got != tc.want {
				t.Fatalf("trailing credential prefix: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCredentialRedactionDropsIncompleteEscapes(t *testing.T) {
	for _, tc := range []struct{ name, secret, prefix, escape string }{
		{"unicode escape", "provider-owned-secret", "provider-owned-secre", `\u0074`},
		{"surrogate pair", "provider-owned-🔐secret", "provider-owned-", `\ud83d\udd10`},
	} {
		for cut := 1; cut < len(tc.escape); cut++ {
			t.Run(fmt.Sprintf("%s/cut=%d", tc.name, cut), func(t *testing.T) {
				_, redact := WithCredentialRedaction(t.Context(), tc.secret)
				body := `{"error":{"message":"rejected ` + tc.prefix + tc.escape[:cut]
				got := redact(&Error{Status: 400, Body: body}).(*Error).Body
				want := `{"error":{"message":"rejected ***`
				if got != want {
					t.Fatalf("truncated escape: got %q, want %q", got, want)
				}
			})
		}
	}
	// Complete escapes must survive, even at the end of an invalid JSON body.
	for _, tc := range []struct{ body, want string }{
		{`{"message":"ordinary\u0021`, `{"message":"ordinary!`},
		{`{"message":"ordinary\\`, `{"message":"ordinary\`},
		{`{"message":"ordinary\ud83d\udd10`, `{"message":"ordinary🔐`},
		{`{"message":"ordinary\\u007`, `{"message":"ordinary\u007`},
	} {
		if got := sanitize(tc.body); got != tc.want {
			t.Errorf("complete escape changed: got %q, want %q", got, tc.want)
		}
	}
}
