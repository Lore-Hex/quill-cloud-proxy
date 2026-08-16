//go:build linux

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
)

func TestUserModelDisconnectWatcherUnwrapsProductionTLSChain(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tlsServer, err := enclavetls.NewSelfSigned("localhost")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := tlsServer.Wrap(tcpListener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := wrapper.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	peer, err := net.Dial("tcp", tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-accepted
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	disconnected := userModelClientDisconnect(ctx, &responseStatsConn{Conn: serverConn})
	if disconnected == nil {
		t.Fatal("production tracked TLS chain did not expose its TCP syscall connection")
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect watcher did not fire after peer close")
	}
}
