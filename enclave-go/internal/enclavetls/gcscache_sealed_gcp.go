//go:build cloud_gcp

package enclavetls

import (
	"errors"

	"golang.org/x/crypto/acme/autocert"
)

func platformGCSCache(_ string) (autocert.Cache, error) {
	return nil, errors.New("GCP shared ACME requires attested key release")
}

func NewSealedGCSCache(bucket, key string, tokens cacheAccessTokenSource, wrapper CacheKeyWrapper) (autocert.Cache, error) {
	if bucket == "" || key == "" || tokens == nil || wrapper == nil {
		return nil, errors.New("incomplete sealed ACME cache configuration")
	}
	return &sealedACMECache{newObjectCache(bucket, tokens), wrapper, bucket, key}, nil
}
