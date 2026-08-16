//go:build linux

package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUserModelClientDisconnectObservesHangupWithoutReading(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	disconnected := userModelClientDisconnect(ctx, server)
	if disconnected == nil {
		t.Fatal("TCP connection did not expose a disconnect signal")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("peer hangup was not observed")
	}
}
