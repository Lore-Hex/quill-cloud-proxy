//go:build llm_multi

package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestDatabricksUnityDispatch(t *testing.T) {
	const workspace = "dbc-test.cloud.databricks.com"
	for _, tc := range []struct{ name, token, upstream, path, key, wireModel string }{
		{"migrated", "unity", "databricks-gpt-oss-20b", "/ai-gateway/mlflow/v1", "unity", "system.ai.gpt-oss-20b"},
		{"restricted", "unity", "databricks-kimi-k3", "/serving-endpoints", "old", "databricks-kimi-k3"},
		{"old bundle", "", "databricks-gpt-oss-20b", "/serving-endpoints", "old", "databricks-gpt-oss-20b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(&qtypes.BootstrapData{DatabricksHost: workspace, DatabricksToken: "old", DatabricksUnityToken: tc.token}).(*multiClient)
			calls := 0
			client := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var payload struct{ Model string }
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if r.URL.Scheme != "https" || r.URL.Host != workspace || r.URL.Path != tc.path+"/chat/completions" ||
					payload.Model != tc.wireModel || r.Header.Get("Authorization") != "Bearer "+tc.key {
					t.Fatalf("wrong destination, model or credential: %s %s", r.URL.Path, payload.Model)
				}
				return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
			})}
			m.databricks.httpc = client
			if m.databricksUnity != nil {
				m.databricksUnity.httpc = client
			}
			req := &qtypes.OpenAIChatRequest{Model: "openai/gpt-oss-20b", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "OK"}}}
			body, err := adapter.ToAnthropic(req, req.Model)
			if err != nil {
				t.Fatal(err)
			}
			err = m.InvokeStreaming(t.Context(), req, body, io.Discard, InvokeOptions{Provider: "databricks", UpstreamModel: tc.upstream})
			if status, _ := HTTPStatusFromError(err); status != http.StatusForbidden || calls != 1 {
				t.Fatalf("expected one call and no cross-gateway replay: status=%d calls=%d", status, calls)
			}
		})
	}
}

func TestDatabricksUnityClosedByDefault(t *testing.T) {
	for _, id := range []string{"", "system.ai.gpt-oss-20b", "databricks-unknown", "databricks-deepseek-v4-1-flash-1017"} {
		if _, ok := databricksUnityModel(id); ok {
			t.Errorf("unexpected Unity route: %q", id)
		}
	}
	if newDatabricksUnity("https://unapproved.invalid", "test") != nil {
		t.Fatal("unapproved host")
	}
}
