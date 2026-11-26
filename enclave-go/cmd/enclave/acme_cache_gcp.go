//go:build cloud_gcp

package main

import (
	"context"
	"net/http"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/crypto/acme/autocert"
)

// Resource identities are part of the measurement, not launch overrides.
// A separate bucket ensures misses never fall back to legacy private keys.
const (
	acmeSealedBucket = "quill-cloud-proxy-acme-sealed-v1"
	acmeSealedKey    = "projects/quill-cloud-proxy/locations/us-central1/keyRings/trusted-router-tls/cryptoKeys/acme-workload-wrap"
	acmeWIF          = "//iam.googleapis.com/projects/44325983244/locations/global/workloadIdentityPools/trustedrouter-batch/providers/confidential-space"
)

func configuredACMECache(_ context.Context, _ *types.BootstrapData) (autocert.Cache, error) {
	client := byokcache.NewVsockKMSClient()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	identity, err := byokcache.NewConfidentialSpaceTokenSource(acmeWIF, client)
	if err != nil {
		return nil, err
	}
	kms := &byokcache.GoogleKMSUnwrapper{HTTPClient: client, TokenSource: identity}
	return enclavetls.NewSealedGCSCache(acmeSealedBucket, acmeSealedKey, identity, kms)
}
