//go:build !cloud_gcp && !cloud_aws

package enclavetls

import "golang.org/x/crypto/acme/autocert"

func platformGCSCache(bucket string) (autocert.Cache, error) {
	return newObjectCache(bucket, &gcpTokenSource{httpClient: newTokenHTTPClient()}), nil
}
