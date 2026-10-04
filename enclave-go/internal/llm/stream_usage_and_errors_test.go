package llm

import (
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestNativeTerminalDoesNotBlockAtEOF(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	done := make(chan error, 1)
	go func() {
		err := relayAnthropicStream(strings.NewReader("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"), pw)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	if _, err := adapter.CollectAnthropicText(pr); err != nil {
		t.Fatal(err)
	}
	// Closing the reader makes an unwanted extra write fail deterministically.
	_ = pr.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNativeMultilineErrorReachesCollector(t *testing.T) {
	for _, end := range []string{"\n\n", ""} {
		t.Run(map[bool]string{true: "terminated", false: "EOF"}[end != ""], func(t *testing.T) {
			wire := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n" +
				"event: error\ndata: {\"type\":\"error\",\n: keepalive\ndata: \"error\":{\"type\":\"overloaded_error\",\"message\":\"overloaded\"}}" + end
			pr, pw := io.Pipe()
			defer pr.Close()
			go func() { _ = pw.CloseWithError(relayAnthropicStream(strings.NewReader(wire), pw)) }()
			result, err := adapter.CollectAnthropicText(pr)
			if err == nil || upstreamerror.Parse(err).Status != 529 {
				t.Fatalf("multiline error became success: result=%+v err=%v", result, err)
			}
		})
	}
}
