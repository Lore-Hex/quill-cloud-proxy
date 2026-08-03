//go:build !cloud_aws

package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func videoProviderKeys(boot *types.BootstrapData) video.ProviderKeys {
	return video.ProviderKeys{
		Venice: boot.VeniceAPIKey, Google: boot.GeminiAPIKey,
		MiniMax: boot.MiniMaxAPIKey, XAI: boot.GrokAPIKey, Alibaba: boot.AlibabaAPIKey,
		AtlasCloud: boot.AtlasCloudAPIKey,
		LTX:        boot.LTXAPIKey, Runway: boot.RunwayAPIKey,
		OpenAI: boot.OpenAIVideoAPIKey, Kling: boot.KlingAPIKey,
	}
}
