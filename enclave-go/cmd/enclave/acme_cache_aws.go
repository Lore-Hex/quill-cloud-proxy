//go:build cloud_aws

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Only replace in reviewed source after GenerateDataKeyPairWithoutPlaintext
// and an independent key-policy audit. Never recover a pin from live traffic,
// parent configuration, an environment variable, or the recipient response.
const nitroTLSCacheSPKI = "4e1a625146a14ff092e8af073fca037405625ee7d2802ed88667144a8fbb52a2"

func configuredACMECache(ctx context.Context, boot *types.BootstrapData) (autocert.Cache, error) {
	if boot == nil || boot.AWSBootstrap == nil || boot.AWSBootstrap.Mode != "attested" || boot.AWSBootstrap.Policy != "strict" {
		return nil, errors.New("Nitro ACME requires strict attested bootstrap")
	}
	if bucket := os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET"); bucket != "" && bucket != enclavetls.AWSSealedBucket {
		return nil, errors.New("unapproved Nitro ACME cache")
	}
	for _, name := range []string{"QUILL_ACME_DIRECTORY_URL", "QUILL_ACME_FALLBACK_DIRECTORY_URL"} {
		switch os.Getenv(name) {
		case "", acme.LetsEncryptURL, "https://dv.acme-v02.api.pki.goog/directory", "https://acme.zerossl.com/v2/DV90":
		default:
			return nil, errors.New("unapproved Nitro ACME directory")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	key, err := bootstrap.FetchNitroTLSCacheKey(ctx, nitroTLSCacheSPKI)
	defer clear(key)
	if err != nil {
		return nil, err
	}
	return enclavetls.NewNitroACMECache(key, nitroTLSCacheSPKI)
}
