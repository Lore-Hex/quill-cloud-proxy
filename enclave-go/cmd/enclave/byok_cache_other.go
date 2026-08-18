//go:build !cloud_azure

package main

import "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"

func newBYOKSecretCache() *byokcache.Cache {
	kmsHTTP := byokcache.NewVsockKMSClient()
	return byokcache.New(byokcache.Options{
		Unwrapper: &byokcache.GoogleKMSUnwrapper{
			HTTPClient:  kmsHTTP,
			TokenSource: byokcache.NewMetadataTokenSource(kmsHTTP),
		},
	})
}
