//go:build cloud_aws && linux

package privatemode

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// Keep these verification/data tunnels aligned with deploy-aws-nitro.sh.
// The host forwards TLS bytes only. CONNECT runs INSIDE our enclave.
var tunnels = map[string]uint32{
	"api.privatemode.ai:443":                     8100,
	"kdsintf.amd.com:443":                        8101,
	"api.trustedservices.intel.com:443":          8051,
	"certificates.trustedservices.intel.com:443": 8102,
}

func platformEnvironment(ctx context.Context) ([]string, func(), error) {
	if err := enableLoopback(); err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		port, ok := tunnels[strings.ToLower(r.Host)]
		if !ok || r.Method != http.MethodConnect {
			http.Error(w, "destination denied", http.StatusForbidden)
			return
		}
		upstream, err := vsock.Dial(3, port, nil)
		if err != nil {
			http.Error(w, "tunnel unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = upstream.Close() })
		defer stop()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		<-done
	})}
	go func() { _ = srv.Serve(listener) }()
	return []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt", "HTTPS_PROXY=http://" + listener.Addr().String(), "HTTP_PROXY=http://" + listener.Addr().String()},
		func() { _ = srv.Close() }, nil
}

func enableLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	req, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, req); err != nil {
		return err
	}
	if req.Uint16()&unix.IFF_UP != 0 {
		return nil
	}
	req.SetUint16(req.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, req); err != nil {
		return errors.New("privatemode: loopback unavailable")
	}
	return nil
}
