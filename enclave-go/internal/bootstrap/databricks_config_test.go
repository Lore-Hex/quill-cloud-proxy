package bootstrap

import (
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestValidateDatabricksBootstrapDisabled(t *testing.T) {
	t.Parallel()
	data := &types.BootstrapData{}
	if err := validateDatabricksBootstrap(data); err != nil {
		t.Fatalf("disabled Databricks configuration: %v", err)
	}
}

func TestValidateDatabricksBootstrapRequiresPair(t *testing.T) {
	t.Parallel()
	for _, data := range []*types.BootstrapData{
		{DatabricksToken: "token-only"},
		{DatabricksHost: "dbc-1234.cloud.databricks.com"},
	} {
		err := validateDatabricksBootstrap(data)
		if err == nil || !strings.Contains(err.Error(), "configured together") {
			t.Fatalf("validateDatabricksBootstrap(%+v) error = %v", data, err)
		}
	}
}

func TestValidateDatabricksBootstrapNormalizesApprovedHost(t *testing.T) {
	t.Parallel()
	data := &types.BootstrapData{
		DatabricksToken: "  token  ",
		DatabricksHost:  " DBC-1234.CLOUD.DATABRICKS.COM/ ",
	}
	if err := validateDatabricksBootstrap(data); err != nil {
		t.Fatalf("validateDatabricksBootstrap: %v", err)
	}
	if data.DatabricksToken != "token" {
		t.Fatalf("token was not trimmed")
	}
	if data.DatabricksHost != "https://dbc-1234.cloud.databricks.com" {
		t.Fatalf("host = %q", data.DatabricksHost)
	}
}

func TestValidateDatabricksBootstrapRejectsUnapprovedHost(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"http://dbc-1234.cloud.databricks.com",
		"https://dbc-1234.cloud.databricks.com:8443",
		"https://user@dbc-1234.cloud.databricks.com",
		"https://dbc-1234.cloud.databricks.com/path",
		"https://cloud.databricks.com.evil.example",
	}
	for _, host := range invalid {
		data := &types.BootstrapData{DatabricksToken: "token", DatabricksHost: host}
		if err := validateDatabricksBootstrap(data); err == nil {
			t.Errorf("host %q was accepted", host)
		}
	}
}
