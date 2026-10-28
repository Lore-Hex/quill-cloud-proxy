package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type startupPipeListener struct {
	conn chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *startupPipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conn:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *startupPipeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*startupPipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "startup-test", Net: "pipe"} }

func TestStartupRealServingHandoff(t *testing.T) {
	if os.Getenv("STARTUP_SERVING_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupRealServingHandoff$") //nolint:gosec // Relaunch this test binary with fixed arguments.
		cmd.Env = append(os.Environ(), "STARTUP_SERVING_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("serving handoff: %v\n%s", err, out)
		}
		return
	}

	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
	t.Setenv("TR_SHADOW_V2_STARTUP_MANIFEST", "configured-test-input")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &startupPipeListener{make(chan net.Conn, 1), make(chan struct{}), sync.Once{}}
	server, peer := net.Pipe()
	defer peer.Close()
	l.conn <- server
	done := make(chan error, 1)
	go func() {
		_, err := serveWithShadowV2Startup(ctx, l, time.Now(), r, true, nil, nil, nil, func(_ context.Context, c net.Conn) {
			request, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return
			}
			defer request.Body.Close()
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nordinary")
		})
		done <- err
	}()
	_ = peer.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err = io.WriteString(peer, "GET /ready HTTP/1.1\r\nHost: local\r\n\r\n"); err != nil {
		t.Error("startup held serving", err)
	} else {
		response, e := http.ReadResponse(bufio.NewReader(peer), nil)
		if e != nil {
			t.Error(e)
		} else {
			body, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || string(body) != "ordinary" {
				t.Error("ordinary response changed")
			}
		}
	}
	if trustedrouter.EnclaveOptedAdmission() {
		t.Error("unfinished descriptor made admission available")
	}
	cancel()
	_ = w.Close()
	select {
	case err = <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serving did not stop")
	}
	// Restore the dormant startup state before the package's other tests.
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "off")
}
