package directproviders

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestSpecsAreValidAndImmutable(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	all := All()
	if len(all) != 18 {
		t.Fatalf("provider specs = %d, want 18", len(all))
	}
	original := all[0]
	all[0].Provider = "mutated"
	got, ok := Lookup(original.Provider)
	if !ok || got != original {
		t.Fatalf("All exposed mutable package state: got %#v, ok=%v", got, ok)
	}
}

func TestLookupRequiresCanonicalSlug(t *testing.T) {
	for _, provider := range []string{"AION-LABS", "aion_labs", " aion-labs "} {
		if _, ok := Lookup(provider); ok {
			t.Errorf("Lookup(%q) accepted a non-canonical alias", provider)
		}
	}
	if spec, ok := Lookup("aion-labs"); !ok || spec.BaseURL != "https://api.aionlabs.ai/v1" {
		t.Fatalf("Lookup(aion-labs) = %#v, %v", spec, ok)
	}
}

func TestCloudConfigurationsCoverEverySpec(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(value)
	}

	awsParent := read("../../../parent/src/quill_parent/bootstrap_server.py")
	awsSync := read("../../../tools/sync-secrets-to-aws.sh")
	gcpMIG := read("../../../tools/deploy-gcp-mig.sh")
	gcpBootstrap := read("../../../tools/deploy-gcp-bootstrap.sh")
	azureDeploy := read("../../../tools/deploy-azure-aci.sh")
	azureSealer := read("../../../tools/azure-seal-bundle.py")
	dockerPolicy := read("../../Dockerfile.enclave.gcp.multi")
	awsClient := read("../llm/http_client_aws.go")
	awsDeploy := read("../../../tools/deploy-aws-nitro.sh")

	parentBlock := regexp.MustCompile(`(?s)_DIRECT_PROVIDER_KEYS:.*?= \((.*?)\)\n\n`).FindStringSubmatch(awsParent)
	if len(parentBlock) != 2 {
		t.Fatal("AWS parent direct-provider table was not found")
	}
	parentRows := regexp.MustCompile(`\("([a-z0-9-]+)", "([a-z0-9-]+)"\)`).FindAllStringSubmatch(parentBlock[1], -1)
	parent := make(map[string]string, len(parentRows))
	for _, row := range parentRows {
		parent[row[1]] = row[2]
	}
	if len(parent) != len(specs) {
		t.Fatalf("AWS parent direct providers = %d, want %d", len(parent), len(specs))
	}

	for _, spec := range specs {
		if parent[spec.Provider] != spec.SecretName {
			t.Errorf("AWS parent %s secret = %q, want %q", spec.Provider, parent[spec.Provider], spec.SecretName)
		}
		for path, source := range map[string]string{
			"AWS secret sync": awsSync,
			"GCP MIG":         gcpMIG,
			"GCP bootstrap":   gcpBootstrap,
			"Azure deploy":    azureDeploy,
			"Azure sealer":    azureSealer,
		} {
			usesSealedEnvCoordinate := path == "Azure deploy" || path == "Azure sealer"
			if !strings.Contains(source, spec.SecretName) && !usesSealedEnvCoordinate {
				t.Errorf("%s is missing %s", path, spec.SecretName)
			}
			if usesSealedEnvCoordinate && !strings.Contains(source, spec.SecretEnv) {
				t.Errorf("%s is missing %s", path, spec.SecretEnv)
			}
		}
		if !strings.Contains(dockerPolicy, spec.SecretEnv) {
			t.Errorf("GCP image policy is missing %s", spec.SecretEnv)
		}
		parsed, err := url.Parse(spec.BaseURL)
		if err != nil {
			t.Fatalf("parse %s base URL: %v", spec.Provider, err)
		}
		for path, source := range map[string]string{
			"AWS enclave client": awsClient,
			"AWS parent deploy":  awsDeploy,
		} {
			if !strings.Contains(source, parsed.Hostname()) {
				t.Errorf("%s is missing %s", path, parsed.Hostname())
			}
		}
	}
}
