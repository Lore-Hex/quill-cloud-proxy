//go:build cloud_aws

// Package bootstrap fetches the BootstrapData from the parent over vsock.
//
// At enclave startup the parent listens on (CID 3, port 9100) and emits one
// JSON-encoded BootstrapData per accepted connection. The enclave dials,
// reads, then closes. Any subsequent device-list refresh uses the same
// channel.
//
// NB: vsock port 9000 is reserved by `nitro-cli run-enclave` for the boot
// heartbeat between the host and the enclave. We pick 9100 to avoid that
// collision (E36 "vsock bind error").
//
// V1 trust caveat: parent fetches the device-key blob from S3 and KMS-decrypts
// it (parent has the IAM perms for both), then ships plaintext over vsock.
// Parent therefore *can* see the device-key list. V1.1 will switch to
// KMS-attested decrypt where parent only forwards encrypted-to-enclave bytes.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/mdlayher/vsock"
)

// ParentCID and BootstrapPort are the well-known coordinates the parent
// listens on for bootstrap RPC.
const (
	ParentCID     uint32 = 3
	BootstrapPort uint32 = 9100
)

// Fetch dials the parent and reads one BootstrapData. Retries with backoff
// for up to ~30 seconds since the enclave can boot before the parent's
// listener is ready.
func Fetch(ctx context.Context) (*types.BootstrapData, error) {
	var lastErr error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		conn, err := vsock.Dial(ParentCID, BootstrapPort, nil)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		body, err := io.ReadAll(conn)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		var data types.BootstrapData
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("bootstrap: parse: %w", err)
		}
		return &data, nil
	}
	return nil, fmt.Errorf("bootstrap: timed out fetching from parent: %w", lastErr)
}
