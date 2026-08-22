package bootstrap

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestDirectProviderSecretSpecsAreDistinctAndAssignByProvider(t *testing.T) {
	if err := directproviders.Validate(); err != nil {
		t.Fatal(err)
	}
	var data types.BootstrapData
	for _, spec := range directproviders.All() {
		assignDirectProviderAPIKey(&data, spec.Provider, " key-"+spec.Provider+" ")
	}
	if len(data.ProviderAPIKeys) != len(directproviders.All()) {
		t.Fatalf("provider keys = %d, want %d", len(data.ProviderAPIKeys), len(directproviders.All()))
	}
	for _, spec := range directproviders.All() {
		if got, want := data.ProviderAPIKeys[spec.Provider], "key-"+spec.Provider; got != want {
			t.Errorf("%s key = %q, want %q", spec.Provider, got, want)
		}
	}
}

func TestResolveDirectProviderSecretNames(t *testing.T) {
	for _, spec := range directproviders.All() {
		t.Setenv(spec.SecretEnv, "")
	}
	t.Setenv("QUILL_NEXTBIT_SECRET", " trustedrouter-nextbit-api-key ")
	names, err := resolveDirectProviderSecretNames("bootstrap/test")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names["nextbit"] != "trustedrouter-nextbit-api-key" {
		t.Fatalf("resolved names = %#v", names)
	}
}

func TestResolveDirectProviderSecretNamesRejectsWhitespace(t *testing.T) {
	for _, spec := range directproviders.All() {
		t.Setenv(spec.SecretEnv, "")
	}
	t.Setenv("QUILL_NEXTBIT_SECRET", " \t ")
	if _, err := resolveDirectProviderSecretNames("bootstrap/test"); err == nil {
		t.Fatal("whitespace-only secret name was accepted")
	}
}
