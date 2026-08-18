//go:build cloud_azure

package main

import (
	"fmt"
	"os"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
)

func newBYOKSecretCache() *byokcache.Cache {
	// Existing envelopes are wrapped by GCP KMS. Azure must not reach back to
	// GCP to unwrap them. Until the control plane emits an Azure-local envelope,
	// encrypted BYOK and user-model credentials fail closed while credits routes
	// continue normally.
	fmt.Fprintln(os.Stderr, "byokcache.disabled cloud=azure reason=azure_local_envelope_not_configured")
	return nil
}
