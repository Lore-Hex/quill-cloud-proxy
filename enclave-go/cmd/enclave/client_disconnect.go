package main

import (
	"context"
	"io"
	"sync/atomic"
)

func cancelOnClientDisconnect(
	ctx context.Context,
	cancel context.CancelFunc,
	conn io.Writer,
) *atomic.Bool {
	closed := &atomic.Bool{}
	disconnected := clientDisconnect(ctx, conn)
	if disconnected == nil {
		return closed
	}
	go func() {
		select {
		case <-disconnected:
			closed.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()
	return closed
}
