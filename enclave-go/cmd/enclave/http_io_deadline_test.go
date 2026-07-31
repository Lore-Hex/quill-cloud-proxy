package main

import (
	"net"
	"testing"
	"time"
)

func TestResponseWriteTimesOutWhenClientStopsReading(t *testing.T) {
	oldTimeout := responseWriteTimeout
	responseWriteTimeout = 50 * time.Millisecond
	t.Cleanup(func() { responseWriteTimeout = oldTimeout })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &responseStatsConn{Conn: server}

	started := time.Now()
	if _, err := conn.Write([]byte("blocked response")); err == nil {
		t.Fatal("stalled write unexpectedly succeeded")
	}
	elapsed := time.Since(started)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("stalled write returned too early after %s", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("stalled write remained blocked for %s", elapsed)
	}
}
