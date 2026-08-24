//go:build cloud_aws

package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func imageProviderKeys(boot *types.BootstrapData) imagegen.ProviderKeys {
	// Nitro can enable only providers whose fixed hosts exist in the measured
	// parent tunnel allowlist. Keep the new direct providers dark until those
	// tunnels and any result-delivery hosts are explicitly added and attested.
	return imagegen.ProviderKeys{
		OpenAI: boot.OpenAIAPIKey, XAI: boot.GrokAPIKey,
		Nscale: boot.ProviderAPIKeys["nscale"],
	}
}
