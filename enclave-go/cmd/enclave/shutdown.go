package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Leave time for forced cancellation and the settlement queue before the host
// terminates the process. DNS draining alone cannot drain pinned connections.
const requestCancelTimeout = 10 * time.Second

type connectionDrain struct {
	mu       sync.Mutex
	draining bool
	shutdown context.Context
	active   map[*drainConnection]bool
}

type drainConnection struct {
	owner *connectionDrain
	conn  net.Conn
}

type drainConnectionKey struct{}

func beginConnectionRequest(ctx context.Context) bool {
	c, ok := ctx.Value(drainConnectionKey{}).(*drainConnection)
	if !ok {
		return ctx.Err() == nil
	}
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	if c.owner.draining || c.owner.shutdown.Err() != nil {
		return false
	}
	c.owner.active[c] = true
	return true
}

func markConnectionIdle(ctx context.Context) bool {
	c, ok := ctx.Value(drainConnectionKey{}).(*drainConnection)
	if !ok {
		return ctx.Err() == nil
	}
	c.owner.mu.Lock()
	c.owner.active[c] = false
	draining := c.owner.draining || c.owner.shutdown.Err() != nil
	c.owner.mu.Unlock()
	if draining {
		_ = c.conn.SetWriteDeadline(time.Now())
		_ = c.conn.Close()
	}
	return !draining
}

func (d *connectionDrain) closeConnections(force bool) int {
	d.mu.Lock()
	d.draining = true
	var closing []net.Conn
	active := 0
	for c, busy := range d.active {
		if busy {
			active++
		}
		if force || !busy {
			closing = append(closing, c.conn)
		}
	}
	d.mu.Unlock()
	for _, conn := range closing {
		// Bound TLS close_notify writes to clients which stopped reading.
		_ = conn.SetWriteDeadline(time.Now())
		_ = conn.Close()
	}
	return active
}

func serveUntilCanceled(ctx context.Context, listener net.Listener, handle func(context.Context, net.Conn)) error {
	return serveWithDrain(ctx, listener, handle, requestDrainTimeout, requestCancelTimeout)
}

func serveWithDrain(ctx context.Context, listener net.Listener, handle func(context.Context, net.Conn), grace, cleanup time.Duration) error {
	defer listener.Close()
	requestContext, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	drain := &connectionDrain{active: make(map[*drainConnection]bool), shutdown: ctx}
	var handlers sync.WaitGroup
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-watcherDone:
		}
	}()
	defer close(watcherDone)
	var acceptErr error
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				acceptErr = fmt.Errorf("accept: %w", err)
			}
			break
		}
		if ctx.Err() != nil {
			_ = conn.Close()
			break
		}
		c := &drainConnection{owner: drain, conn: conn}
		drain.mu.Lock()
		drain.active[c] = true
		drain.mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() {
				drain.mu.Lock()
				delete(drain.active, c)
				drain.mu.Unlock()
				_ = conn.SetWriteDeadline(time.Now())
				_ = conn.Close()
			}()
			handle(context.WithValue(requestContext, drainConnectionKey{}, c), conn)
		}()
	}
	active := drain.closeConnections(false)
	fmt.Fprintf(os.Stderr, "enclave.shutdown_drain active=%d grace_ms=%d\n", active, grace.Milliseconds())
	done := make(chan struct{})
	go func() {
		handlers.Wait()
		close(done)
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return acceptErr
	case <-timer.C:
		cancelRequests()
		active = drain.closeConnections(true)
		fmt.Fprintf(os.Stderr, "enclave.shutdown_forced active=%d\n", active)
	}
	cleanupTimer := time.NewTimer(cleanup)
	defer cleanupTimer.Stop()
	select {
	case <-done:
	case <-cleanupTimer.C:
		fmt.Fprintln(os.Stderr, "enclave.shutdown_handlers_pending")
	}
	return acceptErr
}

func shutdownHealthHandler(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if ctx.Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "draining\n")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
}
