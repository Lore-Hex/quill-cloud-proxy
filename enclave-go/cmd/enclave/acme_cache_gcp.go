//go:build cloud_gcp

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/crypto/acme/autocert"
)

// Resource identities are part of the measurement, not launch overrides.
// A separate bucket ensures misses never fall back to legacy private keys.
const (
	acmeSealedBucket = "quill-cloud-proxy-acme-sealed-v1"
	acmeSealedKey    = "projects/quill-cloud-proxy/locations/us-central1/keyRings/trusted-router-tls/cryptoKeys/acme-workload-wrap-v2"
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

// This launch mode uses exactly the serving image and cache, but exits before
// bootstrap, TLS issuance or listening. Never log lower-level token responses.
func checkGCPCacheCustody() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cache, err := configuredACMECache(ctx, nil)
	if err != nil {
		return errors.New("cache configuration failed")
	}
	return probeGCPCache(ctx, cache)
}

func probeGCPCache(ctx context.Context, c autocert.Cache) (retErr error) {
	var id [16]byte
	var sample [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return errors.New("probe entropy unavailable")
	}
	if _, err := rand.Read(sample[:]); err != nil {
		return errors.New("probe entropy unavailable")
	}
	name := "__tr_custody_probe__/" + hex.EncodeToString(id[:])
	// Refuse to overwrite any existing object. No caller-selected name or payload.
	if _, err := c.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
		return errors.New("new probe object is not verifiably absent")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := c.Delete(cleanup, name); err != nil {
			retErr = errors.Join(retErr, errors.New("probe cleanup failed"))
		}
	}()
	if err := c.Put(ctx, name, sample[:]); err != nil {
		return errors.New("sealed write failed")
	}
	got, err := c.Get(ctx, name)
	if err != nil || !bytes.Equal(got, sample[:]) {
		return errors.New("sealed readback failed")
	}
	return nil
}
