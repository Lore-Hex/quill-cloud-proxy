//go:build !cloud_aws

package llm

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// Optional unauthenticated reachability only: no prompts, customer data,
// credentials or paid inference. Provider availability is not a CI gate.
func TestProviderEgressLiveReachability(t *testing.T) {
	if os.Getenv("QUILL_LIVE_PROVIDER_EGRESS_SMOKE") != "1" {
		t.Skip("optional public provider egress smoke")
	}
	client := NewProviderHTTPClient()
	defer client.CloseIdleConnections()
	for _, endpoint := range []string{
		"https://api.openai.com/v1/models",
		"https://api.deepseek.com/models",
		"https://generativelanguage.googleapis.com/v1beta/models",
		"https://trustedrouter-foundry-eastus2.openai.azure.com/openai/v1/models",
		"https://dbc-7ccfd8c0-c0da.cloud.databricks.com/api/2.0/serving-endpoints",
	} {
		t.Run(endpoint, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			if resp.StatusCode >= 500 {
				t.Fatalf("provider HTTP %d", resp.StatusCode)
			}
			t.Logf("approved TLS endpoint reached: HTTP %d", resp.StatusCode)
		})
	}
}
