//go:build !cloud_aws

package privatemode

import "context"

func platformEnvironment(context.Context) ([]string, func(), error) {
	return []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}, func() {}, nil
}
