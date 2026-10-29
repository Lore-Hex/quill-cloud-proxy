package maple

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

func tunnelHandler(ctx context.Context, dial func() (net.Conn, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "enclave.trymaple.ai:443" ||
			r.URL.Host != r.Host || r.URL.User != nil || r.URL.RawQuery != "" || r.URL.Path != "" {
			http.Error(w, "destination denied", http.StatusForbidden)
			return
		}
		if ctx.Err() != nil {
			http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
			return
		}
		upstream, err := dial()
		if err != nil {
			http.Error(w, "tunnel unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "tunnel unavailable", http.StatusBadGateway)
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		deadline := time.Now().Add(10 * time.Minute)
		_ = conn.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = upstream.Close() })
		defer stop()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if buffered.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		<-done
	})
}
