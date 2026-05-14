//go:build cloud_aws

// Package bootstrap loads the workload's BootstrapData at enclave startup.
//
// One adapter per cloud, build-tag-selected:
//
//	bootstrap_aws.go   //go:build cloud_aws   — this file
//	bootstrap_gcp.go   //go:build cloud_gcp   — Confidential Space variant
//	bootstrap_<cloud>.go — add a new sibling when onboarding Azure /
//	                       Oracle / etc.
//
// Each adapter exports a single `Fetch(ctx) (*types.BootstrapData, error)`
// function. The build tag selects exactly one per target; the others are
// excluded from the build. No interface file needed — Go's linker
// resolves the symbol at compile time based on the tag.
//
// When adding a new cloud:
//  1. Create `bootstrap_<cloud>.go` with the matching `//go:build`
//     constraint and a `Fetch()` that produces the same BootstrapData.
//  2. Wire any new `*APIKey` fields in `internal/types/types.go` if
//     the cloud has its own secret-store conventions to read.
//  3. Update the build tooling (Dockerfile + deploy script) to set
//     `-tags cloud_<cloud>` and pass the necessary tee-env / boot-time
//     knobs the new adapter reads from os.Getenv.
//
// AWS variant — this file
// =======================
// On Nitro the parent EC2 host listens on (vsock CID 3, port 9100) and
// emits one JSON-encoded BootstrapData per accepted connection. The
// enclave dials, reads, closes. Any subsequent device-list refresh
// reuses the same channel.
//
// NB: vsock port 9000 is reserved by `nitro-cli run-enclave` for the
// boot heartbeat between host and enclave. We pick 9100 to avoid that
// collision (E36 "vsock bind error").
//
// V1 trust caveat: the parent fetches the device-key blob from AWS
// Secrets Manager + KMS-decrypts it (parent has the IAM perms for both)
// then ships plaintext over vsock. Parent therefore *can* see the
// device-key list. V1.1 will switch to KMS-attested decrypt where the
// parent only forwards encrypted-to-enclave bytes and the enclave
// uses Nitro's NSM-attested KMS-Decrypt to recover plaintext inside.
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
