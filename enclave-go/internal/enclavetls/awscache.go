//go:build cloud_aws

package enclavetls

import (
	"context"
	"crypto/cipher"
	"errors"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

const AWSSealedBucket = "quill-cloud-proxy-aws-acme-sealed-v1"

func platformGCSCache(string) (autocert.Cache, error) {
	return nil, errors.New("AWS ACME requires a Nitro recipient-protected cache")
}

type nitroWrapper struct{ aead cipher.AEAD }

func (w nitroWrapper) WrapDEK(_ context.Context, _ string, dek, aad []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("invalid cache data key")
	}
	return w.aead.Seal(nil, nil, dek, aad), nil
}
func (w nitroWrapper) UnwrapDEK(_ context.Context, _ string, blob, aad []byte) ([]byte, error) {
	if len(blob) != 32+w.aead.Overhead() {
		return nil, errors.New("invalid wrapped cache key")
	}
	return w.aead.Open(nil, nil, blob, aad)
}
func NewNitroACMECache(root []byte, spkiHash string) (autocert.Cache, error) {
	cache, _, err := nitroACMEStorage(root, spkiHash)
	if err != nil {
		return nil, err
	}
	return cache, nil
}

func nitroACMEStorage(root []byte, spkiHash string) (*sealedACMECache, *gcsCache, error) {
	a, err := cacheCipher(root)
	if err != nil {
		return nil, nil, err
	}
	client := newTokenHTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	store := newObjectCache(AWSSealedBucket, &gcpTokenSource{httpClient: client})
	store.httpClient.CheckRedirect = client.CheckRedirect
	return &sealedACMECache{store: store, wrapper: nitroWrapper{a}, bucket: AWSSealedBucket, kmsKey: "nitro-tls-cache-v1/" + spkiHash}, store, nil
}
