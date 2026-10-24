//go:build cloud_gcp

package main

import (
	"errors"

	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
)

// settleOutboxStore is the Batch pattern: the plain-HTTP GCS client with a
// federated token from the Confidential Space attestation, through the same
// workload identity provider Batch uses. storage.googleapis.com and
// sts.googleapis.com are already in the enclave's egress for Batch, so the
// outbox adds no host.
func settleOutboxStore(bucket string) (settleoutbox.Store, error) {
	config, ok := productionBatchConfig()
	if !ok || config.WIFProvider == "" {
		return nil, errors.New("no attested identity provider")
	}
	identity, err := byokcache.NewConfidentialSpaceTokenSource(config.WIFProvider, byokcache.NewVsockKMSClient())
	if err != nil {
		return nil, err
	}
	return batchapi.NewGCSStoreWithTokenSource(bucket, identity), nil
}
