package llm

import (
	"io"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/sse"
)

// Native Anthropic events pass through unchanged after complete-event validation.
func relayAnthropicStream(r io.Reader, w io.Writer) error {
	events := sse.NewReader(r, 1<<20)
	for events.Next() {
		if _, err := io.WriteString(w, events.Event().Raw); err != nil {
			return err
		}
	}
	return events.Err()
}
