//go:build cloud_aws

package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func imageProviderKeys(boot *types.BootstrapData) imagegen.ProviderKeys {
	// Nitro can enable only providers whose fixed hosts exist in the measured
	// parent tunnel allowlist. Riverflow's fixed API host is tunneled; result
	// URLs use the authenticated control-plane image fetcher, which repeats the
	// same SSRF, byte, format, dimension, and pixel checks as the direct path.
	return imagegen.ProviderKeys{
		OpenAI: boot.OpenAIAPIKey, XAI: boot.GrokAPIKey,
		Nscale:    boot.ProviderAPIKeys["nscale"],
		Riverflow: boot.ProviderAPIKeys["riverflow"],
	}
}
