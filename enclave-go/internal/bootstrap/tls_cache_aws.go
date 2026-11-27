//go:build cloud_aws

package bootstrap

import (
	"context"
	"net"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap/awssealed"
)

func FetchNitroTLSCacheKey(ctx context.Context, spkiHash string) ([]byte, error) {
	return awssealed.FetchTLSCacheKey(ctx, func(ctx context.Context) (net.Conn, error) {
		return dialBootstrap(ctx, SealedBootstrapPort)
	}, attestBootstrap, spkiHash)
}
