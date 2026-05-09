// Raw TCP pump from the NLB to the enclave's vsock listener.
//
// This binary accepts a raw TCP connection from the NLB and pumps bytes
// bidirectionally to the enclave over vsock: no parsing, no header
// rewrite, no auth check. The enclave terminates TLS on its side;
// everything between the client and the enclave is opaque ciphertext.
//
// Where it sits:
//
//	client ──TLS bytes──▸ NLB :443 (TCP passthrough)
//	                       ─▸ parent:8444 (this binary)
//	                          ─▸ vsock :8001 to enclave (TLS terminator)
//
// Why Go and not Python: this binary sits on the hot path of every
// prompt request. Python asyncio's read+drain has buffer-copy and GIL
// overhead that adds tens of microseconds per chunk. Go's net package
// gives us io.Copy between two net.Conn wrappers — a single user-space
// loop that pushes bytes through the kernel without intermediate
// allocations or interpreter overhead. The previous Python version at
// parent/src/quill_parent/tcp_relay.py is kept for reference but not
// used in production once this binary is wired into the launch
// template's user-data.
//
// The Python parent at parent/src/quill_parent/main.py keeps running
// for /admin/usage, /trust, /health, and the bootstrap RPC server on
// vsock 9000 — those are NOT on the data path so the perf gap there
// doesn't matter.
//
// Configured via env vars (defaults match production):
//
//	QUILL_PUMP_LISTEN_ADDR  default ":8444"
//	QUILL_PUMP_ENCLAVE_CID  default 16  (matches AWS_NITRO_ENCLAVE_CID)
//	QUILL_PUMP_ENCLAVE_PORT default 8001 (matches enclave-go/cmd/enclave/listener_aws.go)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
)

// Defaults match the existing Python pump + the enclave's listener_aws.go
// constants so we can swap at the host level without touching either side.
const (
	defaultListen      = ":8444"
	defaultEnclaveCID  = 16
	defaultEnclavePort = 8001
)

func main() {
	listenAddr := envOrDefault("QUILL_PUMP_LISTEN_ADDR", defaultListen)
	enclaveCID := envIntOrDefault("QUILL_PUMP_ENCLAVE_CID", defaultEnclaveCID)
	enclavePort := envIntOrDefault("QUILL_PUMP_ENCLAVE_PORT", defaultEnclavePort)

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("svc", "parent-pump")

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Error("tcp_pump.listen_failed", "addr", listenAddr, "err", err)
		os.Exit(1)
	}
	defer listener.Close()

	log.Info("tcp_pump.listening",
		"addr", listenAddr,
		"enclave_cid", enclaveCID,
		"enclave_port", enclavePort,
	)

	// Close the listener when context is cancelled so Accept() unblocks
	// and we can do a graceful shutdown.
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		client, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Info("tcp_pump.shutting_down")
				return
			}
			// Don't log per-error here — could spam if the NLB is
			// hammering us. Sample if we ever see this in prod.
			continue
		}

		go handle(client, uint32(enclaveCID), uint32(enclavePort), log)
	}
}

// handle pumps bytes between a single client connection and a
// freshly-dialed vsock connection to the enclave. No buffering, no
// inspection — the only thing that matters is byte-count integrity
// and EOF propagation in both directions.
func handle(client net.Conn, cid, port uint32, log *slog.Logger) {
	defer client.Close()

	// Best-effort TCP keepalive on the NLB side. The NLB sends its
	// own keepalives every 350s; matching that on the parent side
	// prevents idle-connection TCP RST surprises.
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(60 * time.Second)
	}

	enclave, err := vsock.Dial(cid, port, nil)
	if err != nil {
		// Don't include the client address — the parent must not log
		// anything that could correlate to a per-request identity. The
		// enclave-side log already records the connection (without
		// payload). All we need to know on the parent is that vsock
		// dialing failed at all, plus the SO error class for triage.
		log.Error("tcp_pump.dial_enclave_failed", "err", err)
		return
	}
	defer enclave.Close()

	// Two goroutines: client→enclave, enclave→client. As soon as
	// either direction closes (EOF or peer reset), tear down the
	// connection. WaitGroup keeps us alive until both copy goroutines
	// have unwound.
	var wg sync.WaitGroup
	wg.Add(2)

	pump := func(dst, src net.Conn, name string) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		// We deliberately do not log err — most "errors" here are
		// benign EOF / connection-closed-by-peer cases that don't
		// indicate trouble. If the enclave starts dropping connections
		// we'll see it on the enclave side or via NLB target-health.
		_ = err
		// Half-close the destination. CloseWrite signals EOF to the
		// peer without forcing a full RST, which lets the other
		// direction drain gracefully.
		halfClose(dst)
		_ = name
	}

	go pump(enclave, client, "client_to_enclave")
	go pump(client, enclave, "enclave_to_client")

	wg.Wait()
}

// halfClose calls CloseWrite() if the conn supports it, falling back
// to Close() otherwise. *net.TCPConn does; *vsock.Conn does too. This
// lets us send EOF in one direction without tearing down the other.
func halfClose(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: invalid %s=%q, using default %d\n", name, v, def)
			return def
		}
		return n
	}
	return def
}
