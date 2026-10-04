package bedrock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/sse"
)

// RelayEvent validates one complete AWS event-stream payload before emitting
// native Anthropic SSE. AWS supplies record boundaries rather than SSE lines.
func RelayEvent(payload []byte, out io.Writer) error {
	if err := sse.CheckError("", string(payload)); err != nil {
		return err
	}
	var event struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	if event.Type == "" {
		return nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, payload); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "event: %s\ndata: %s\n\n", event.Type, compact.Bytes())
	return err
}
