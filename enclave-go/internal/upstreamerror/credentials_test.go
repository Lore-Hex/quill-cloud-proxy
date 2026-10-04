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
