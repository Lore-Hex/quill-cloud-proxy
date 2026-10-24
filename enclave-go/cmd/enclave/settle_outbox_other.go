//go:build !cloud_gcp

package main

import (
	"errors"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
)

// AWS and Azure enclaves have no attested GCS identity; the outbox stays off
// there even when a bucket is configured.
func settleOutboxStore(string) (settleoutbox.ObjectStore, error) {
	return nil, errors.New("unsupported_cloud")
}
