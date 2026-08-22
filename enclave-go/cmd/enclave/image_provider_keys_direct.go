//go:build !cloud_aws

package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func imageProviderKeys(boot *types.BootstrapData) imagegen.ProviderKeys {
	return imagegen.ProviderKeys{
		OpenAI: boot.OpenAIAPIKey, XAI: boot.GrokAPIKey,
		Decart: boot.DecartAPIKey, Recraft: boot.RecraftAPIKey, BFL: boot.BFLAPIKey,
	}
}
