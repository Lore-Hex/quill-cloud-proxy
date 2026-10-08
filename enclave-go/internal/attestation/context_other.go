//go:build !cloud_gcp

package attestation

import "context"

// GetContext preserves the existing non-GCP hardware backend behavior.
func GetContext(ctx context.Context, leafDER, deviceBlob, nonce, channelBinding, receiptKeyFP []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return Get(leafDER, deviceBlob, nonce, channelBinding, receiptKeyFP)
}
