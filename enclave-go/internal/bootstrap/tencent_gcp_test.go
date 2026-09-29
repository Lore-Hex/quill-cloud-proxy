//go:build cloud_gcp

package bootstrap

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type tencentSecretTransport func(*http.Request) (*http.Response, error)

func (f tencentSecretTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestTencentGCPSecretLoading(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		value  string
		active bool
		fails  bool
	}{
		{"dark", http.StatusOK, "", false, false},
		{"configured", http.StatusOK, " test-key \n", true, false},
		{"missing", http.StatusNotFound, "", true, true},
		{"denied", http.StatusForbidden, "", true, true},
		{"blank", http.StatusOK, " \t\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: tencentSecretTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://secretmanager.googleapis.com/v1/projects/test-project/secrets/trustedrouter-tencent-tokenhub-api-key/versions/latest:access" || r.Header.Get("Authorization") != "Bearer test-token" {
					t.Fatalf("unexpected secret coordinate: %s", r.URL)
				}
				payload := fmt.Sprintf(`{"payload":{"data":%q}}`, base64.StdEncoding.EncodeToString([]byte(tc.value)))
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(payload))}, nil
			})}
			names := map[string]string{}
			if tc.active {
				names["tencent"] = "trustedrouter-tencent-tokenhub-api-key"
			}
			keys, err := fetchDirectProviderAPIKeys(t.Context(), client, "test-token", "test-project", names)
			if (err != nil) != tc.fails {
				t.Fatalf("error = %v, want failure %v", err, tc.fails)
			}
			if tc.active && calls != 1 || !tc.active && calls != 0 {
				t.Fatalf("secret reads = %d, active = %v", calls, tc.active)
			}
			if tc.active && !tc.fails && keys["tencent"] != "test-key" {
				t.Fatal("Tencent secret was not assigned and trimmed")
			}
		})
	}
}
