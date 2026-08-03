//go:build cloud_aws

package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAWSVideoProviderKeysFailClosedToFixedHostRelay(t *testing.T) {
	keys := videoProviderKeys(&types.BootstrapData{
		VeniceAPIKey: "venice", GeminiAPIKey: "google", MiniMaxAPIKey: "minimax",
		GrokAPIKey: "xai", AlibabaAPIKey: "alibaba", LTXAPIKey: "ltx",
		RunwayAPIKey: "runway", OpenAIVideoAPIKey: "openai-video", KlingAPIKey: "kling",
		AtlasCloudAPIKey: "atlas-cloud",
	})
	if keys.Venice != "venice" {
		t.Fatalf("Venice relay key = %q", keys.Venice)
	}
	if keys.Google != "" || keys.MiniMax != "" || keys.XAI != "" || keys.Alibaba != "" ||
		keys.LTX != "" || keys.Runway != "" || keys.OpenAI != "" || keys.Kling != "" || keys.AtlasCloud != "" {
		t.Fatalf("AWS native video adapter unexpectedly enabled: %#v", keys)
	}
}
