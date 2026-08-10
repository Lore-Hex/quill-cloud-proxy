package llm

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func databricksServingBaseURL(rawHost string) (string, error) {
	raw := strings.TrimSpace(rawHost)
	if raw == "" {
		return "", fmt.Errorf("llm/databricks: workspace host is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("llm/databricks: invalid workspace host: %w", err)
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	allowed := strings.HasSuffix(hostname, ".cloud.databricks.com") ||
		strings.HasSuffix(hostname, ".azuredatabricks.net") ||
		strings.HasSuffix(hostname, ".gcp.databricks.com")
	port := parsed.Port()
	if parsed.Scheme != "https" || !allowed || parsed.User != nil ||
		(port != "" && port != "443") || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") ||
		net.ParseIP(hostname) != nil {
		return "", fmt.Errorf("llm/databricks: workspace host is not approved")
	}
	return "https://" + hostname + "/serving-endpoints", nil
}

func newDatabricks(host string, token string) *openAICompatibleClient {
	baseURL, err := databricksServingBaseURL(host)
	if err != nil {
		// Bootstrap rejects invalid paired Databricks configuration before this
		// constructor runs. Keeping the client inert is still safer than falling
		// back to an unrelated provider if a unit test bypasses bootstrap.
		baseURL = ""
	}
	return newOpenAICompatibleAt("databricks", baseURL, token)
}
