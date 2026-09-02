//go:build !cloud_aws

package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestDirectVideoProviderKeysIncludeConfiguredNativeProviders(t *testing.T) {
	keys := videoProviderKeys(&types.BootstrapData{
		VeniceAPIKey: "venice", GeminiAPIKey: "google", MiniMaxAPIKey: "minimax",
		GrokAPIKey: "xai", AlibabaAPIKey: "alibaba", LTXAPIKey: "ltx",
		RunwayAPIKey: "runway", OpenAIVideoAPIKey: "openai-video", KlingAPIKey: "kling",
		AtlasCloudAPIKey: "atlas-cloud", ProviderAPIKeys: map[string]string{"fal": "fal"},
	})
	if keys.Venice == "" || keys.FAL == "" || keys.Google == "" || keys.MiniMax == "" || keys.XAI == "" ||
		keys.Alibaba == "" || keys.LTX == "" || keys.Runway == "" || keys.OpenAI == "" ||
		keys.Kling == "" || keys.AtlasCloud == "" {
		t.Fatalf("configured direct provider key was dropped: %#v", keys)
	}
}
