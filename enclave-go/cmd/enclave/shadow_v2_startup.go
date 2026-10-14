package main

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Keep the production startup-to-serving handoff in one place so it can be
// exercised with the real serving loop and an in-memory listener.
func serveWithShadowV2Startup(ctx context.Context, listener net.Listener, start time.Time, fd *os.File, present bool, boot *qtypes.BootstrapData, client *trustedrouter.Client, image func() (string, []byte), handle func(context.Context, net.Conn)) (*trustedrouter.ShadowV2StartupHarness, error) {
	h := trustedrouter.StartShadowV2Startup(ctx, start, fd, present, boot, client, image)
	return h, serveUntilCanceled(ctx, listener, handle)
}
