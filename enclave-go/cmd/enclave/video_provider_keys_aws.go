//go:build cloud_aws

package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func videoProviderKeys(boot *types.BootstrapData) video.ProviderKeys {
	// Nitro exposes only fixed, audited TLS tunnel hosts. fal H3 Max is safe on
	// this path because sync_mode returns the MP4 inline through queue.fal.run.
	return video.ProviderKeys{Venice: boot.VeniceAPIKey, FAL: boot.ProviderAPIKeys["fal"]}
}
