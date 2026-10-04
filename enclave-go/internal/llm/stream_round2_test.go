package llm

import (
	"io"
	"strings"
	"testing"
	"time"

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
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		_ = pr.Close()
		<-done
		t.Fatal("provider blocked writing empty EOF event after terminal")
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
