//go:build cloud_aws

package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAWSImageProviderKeysIncludeOnlyTunneledProviderWave(t *testing.T) {
	keys := imageProviderKeys(&types.BootstrapData{
		OpenAIAPIKey: "openai", GrokAPIKey: "grok", DecartAPIKey: "decart",
		RecraftAPIKey: "recraft", BFLAPIKey: "bfl",
		ProviderAPIKeys: map[string]string{
			"nscale": "nscale", "krea": "must-remain-dark", "riverflow": "riverflow",
		},
	})
	if keys.OpenAI != "openai" || keys.XAI != "grok" || keys.Nscale != "nscale" ||
		keys.Riverflow != "riverflow" {
		t.Fatalf("fixed-host AWS image keys = %#v", keys)
	}
	if keys.Decart != "" || keys.Recraft != "" || keys.BFL != "" || keys.Krea != "" {
		t.Fatalf("untunneled AWS image keys must remain dark: %#v", keys)
	}
}
