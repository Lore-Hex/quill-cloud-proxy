package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Optional real-browser contract check. Ordinary CI remains dependency-free;
// set QUILL_PLAYWRIGHT_MODULE to an installed Playwright module to run this.
func TestBearerCORSRealBrowser(t *testing.T) {
	if os.Getenv("QUILL_PLAYWRIGHT_MODULE") == "" {
		t.Skip("set QUILL_PLAYWRIGHT_MODULE for Chromium CORS smoke")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var connections sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				serveOne(ctx, conn, registryForBearer("browser-key"), &fakeStreamingLLM{}, nil, nil, nil, nil)
			}()
		}
	}()
	defer func() {
		_ = listener.Close()
		<-acceptDone
		connections.Wait()
	}()
	// #nosec G204 -- Fixed test script; the address comes from our loopback listener, not request input.
	command := exec.CommandContext(ctx, "node", "../../../tools/browser-cors-smoke.cjs", "http://"+listener.Addr().String(), "--fixture")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser CORS: %v\n%s", err, output)
	}
	t.Log(string(output))
}
