package bootstrap

import (
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func assignDirectProviderAPIKey(data *types.BootstrapData, provider, value string) {
	if data.ProviderAPIKeys == nil {
		data.ProviderAPIKeys = make(map[string]string)
	}
	data.ProviderAPIKeys[provider] = strings.TrimSpace(value)
}

func resolveDirectProviderSecretNames(prefix string) (map[string]string, error) {
	if err := directproviders.Validate(); err != nil {
		return nil, err
	}
	names := make(map[string]string)
	for _, spec := range directproviders.All() {
		raw, present := os.LookupEnv(spec.SecretEnv)
		if !present || raw == "" {
			continue
		}
		name := strings.TrimSpace(raw)
		if name == "" {
			return nil, fmt.Errorf("%s: %s is whitespace only", prefix, spec.SecretEnv)
		}
		names[spec.Provider] = name
	}
	return names, nil
}
