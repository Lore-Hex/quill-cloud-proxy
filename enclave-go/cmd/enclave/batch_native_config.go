package main

import (
	"strings"

	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// nativeBatchSubmitAllowlist is intentionally part of the measured binary.
// Native provider Batch APIs retain plaintext request/output state under their
// Batch policies, so mutable instance metadata must never be able to enable
// content export. Activation requires a reviewed source change and a new image
// digest. Keep adapters available independently for recovery and cleanup.
const (
	nativeBatchSubmitAllowlist = "openai,parasail"
	parasailNativeBatchBaseURL = "https://api.parasail.io/v1"
)

func nativeBatchProviders(boot *qtypes.BootstrapData) []batchapi.NativeProvider {
	if boot == nil {
		return nil
	}
	providers := make([]batchapi.NativeProvider, 0, 2)
	if strings.TrimSpace(boot.OpenAIAPIKey) != "" {
		providers = append(providers, batchapi.NewOpenAIFileBatchProvider(
			"openai",
			"https://api.openai.com/v1",
			boot.OpenAIAPIKey,
			"/v1/chat/completions",
			"/v1/embeddings",
		))
	}
	if strings.TrimSpace(boot.ParasailAPIKey) != "" {
		providers = append(providers, batchapi.NewOpenAIFileBatchProvider(
			"parasail",
			parasailNativeBatchBaseURL,
			boot.ParasailAPIKey,
			"/v1/chat/completions",
			"/v1/embeddings",
		))
	}
	return providers
}

func nativeBatchSubmitProviders(configured string) []string {
	allowed := make([]string, 0, 2)
	seen := make(map[string]struct{})
	for _, value := range strings.Split(configured, ",") {
		value = strings.ToLower(strings.TrimSpace(value))
		if (value != "openai" && value != "parasail") || value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		allowed = append(allowed, value)
	}
	return allowed
}
