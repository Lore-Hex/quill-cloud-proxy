//go:build cloud_aws

package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAWSImageProviderKeysExcludeUntunneledProviderWave(t *testing.T) {
	keys := imageProviderKeys(&types.BootstrapData{
		OpenAIAPIKey: "openai", GrokAPIKey: "grok", DecartAPIKey: "decart",
		RecraftAPIKey: "recraft", BFLAPIKey: "bfl",
	})
	if keys.OpenAI != "openai" || keys.XAI != "grok" {
		t.Fatalf("fixed-host AWS image keys = %#v", keys)
	}
	if keys.Decart != "" || keys.Recraft != "" || keys.BFL != "" {
		t.Fatalf("untunneled AWS image keys must remain dark: %#v", keys)
	}
}
