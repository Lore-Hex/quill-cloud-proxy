package main

import (
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNativeBatchAdaptersAndMeasuredSubmitAllowlistAreSeparate(t *testing.T) {
	boot := &qtypes.BootstrapData{
		OpenAIAPIKey:   "openai-secret",
		ParasailAPIKey: "parasail-secret",
	}
	providers := nativeBatchProviders(boot)
	if len(providers) != 2 || providers[0].Name() != "openai" || providers[1].Name() != "parasail" {
		t.Fatalf("providers = %#v", providers)
	}
	if nativeBatchSubmitAllowlist != "" {
		t.Fatalf("production submit allowlist must remain dark before explicit approval: %q", nativeBatchSubmitAllowlist)
	}
	if parasailNativeBatchBaseURL != "https://api.parasail.io/v1" {
		t.Fatalf("Parasail Batch base URL = %q", parasailNativeBatchBaseURL)
	}
	allowed := nativeBatchSubmitProviders(" parasail,unknown,openai,parasail ")
	if len(allowed) != 2 || allowed[0] != "parasail" || allowed[1] != "openai" {
		t.Fatalf("allowed = %#v", allowed)
	}
}
