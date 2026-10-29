//go:build cloud_aws && linux

package maple

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// Port 8136 is dedicated to enclave.trymaple.ai:443 on the parent. Both TLS
// and Transport V2 terminate in the measured helper, never on the AWS host.
var mapleTunnel = struct {
	Host string
	CID  uint32
	Port uint32
}{Host: "enclave.trymaple.ai", CID: 3, Port: 8136}

func platformEnvironment(ctx context.Context) ([]string, func(), error) {
	if err := enableLoopback(); err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 4096,
		Handler: tunnelHandler(ctx, func() (net.Conn, error) { return vsock.Dial(mapleTunnel.CID, mapleTunnel.Port, nil) })}
	go func() { _ = server.Serve(listener) }()
	return []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt", "HTTPS_PROXY=http://" + listener.Addr().String()},
		func() { _ = server.Close() }, nil
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
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, req); err != nil {
		return err
	}
	if req.Uint16()&unix.IFF_UP != 0 {
		return nil
	}
	req.SetUint16(req.Uint16() | unix.IFF_UP)
	if unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, req) != nil {
		return errors.New("maple: loopback unavailable")
	}
	return nil
}
