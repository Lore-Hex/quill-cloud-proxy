//go:build !cloud_azure

package attestation

import "context"

func GetRawSNP(context.Context, []byte, []byte, []byte) ([]byte, error) {
	return nil, ErrIssuerUnavailable
}
