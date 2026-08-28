//go:build !cloud_aws

package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestDirectImageProviderKeysIncludeProviderWave(t *testing.T) {
	keys := imageProviderKeys(&types.BootstrapData{
		OpenAIAPIKey: "openai", GrokAPIKey: "grok", DecartAPIKey: "decart",
		RecraftAPIKey: "recraft", BFLAPIKey: "bfl",
		ProviderAPIKeys: map[string]string{"nscale": "nscale", "krea": "krea", "riverflow": "riverflow"},
	})
	if keys.OpenAI != "openai" || keys.XAI != "grok" || keys.Decart != "decart" ||
		keys.Recraft != "recraft" || keys.BFL != "bfl" || keys.Nscale != "nscale" ||
		keys.Krea != "krea" || keys.Riverflow != "riverflow" {
		t.Fatalf("direct image keys = %#v", keys)
	}
}
