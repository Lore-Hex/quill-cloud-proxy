package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// A dropped parameter must not reappear when de-identification re-reads the
// request body.
func TestLenientRequestDeidentifiesTheFilteredBody(t *testing.T) {
	previous := rampartRunner
	defer func() { rampartRunner = previous }()
	rampartRunner = &privacyTestRunner{}
	for _, tc := range []struct{ path, body string }{
		{"/v1/chat/completions", `{"model":"anthropic/claude-opus-5.5","deidentify":true,"extra_body":{"x":1},"store":true,"messages":[{"role":"user","content":"alice@example.com"}]}`},
		{"/v1/responses", `{"model":"anthropic/claude-opus-5.5","deidentify":true,"made_up":1,"store":true,"input":"alice@example.com"}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			digest := sha256.Sum256([]byte("local-test"))
			reg := auth.New([]types.DeviceConfig{{KeyHash: hex.EncodeToString(digest[:]), Owner: "test", DeviceID: "privacy"}})
			server, client := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(40 * time.Second))
			provider := &privacyEchoProvider{}
			done := make(chan struct{})
			go func() { defer close(done); serveOne(context.Background(), server, reg, provider, nil, nil, nil, nil) }()
			if _, err := fmt.Fprintf(client, "POST %s HTTP/1.1\r\nAuthorization: Bearer local-test\r\nX-TrustedRouter-Lenient: true\r\nContent-Length: %d\r\n\r\n%s", tc.path, len(tc.body), tc.body); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			<-done
			if response.StatusCode != 200 || provider.calls == 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.StatusCode, provider.calls, data)
			}
			if response.Header.Get(ignoredParametersHeader) == "" {
				t.Fatal("ignored parameters header missing")
			}
		})
	}
}
