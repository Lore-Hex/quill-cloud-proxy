package bootstrap

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func validateDatabricksBootstrap(data *types.BootstrapData) error {
	host := strings.TrimSpace(data.DatabricksHost)
	token := strings.TrimSpace(data.DatabricksToken)
	if host == "" && token == "" {
		return nil
	}
	if host == "" || token == "" {
		return fmt.Errorf("databricks host and token must be configured together")
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	parsed, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("databricks workspace host is invalid: %w", err)
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	allowed := strings.HasSuffix(hostname, ".cloud.databricks.com") ||
		strings.HasSuffix(hostname, ".azuredatabricks.net") ||
		strings.HasSuffix(hostname, ".gcp.databricks.com")
	if parsed.Scheme != "https" || !allowed || parsed.User != nil ||
		(parsed.Port() != "" && parsed.Port() != "443") || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("databricks workspace host is not approved")
	}
	data.DatabricksHost = "https://" + hostname
	data.DatabricksToken = token
	return nil
}
