package llm

import (
	"bufio"
	"io"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// Native Anthropic events still pass through unchanged, except failures must
// reach the gateway as errors rather than becoming a successful empty stream.
func relayAnthropicStream(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var event strings.Builder
	flush := func() error {
		_, err := io.WriteString(w, event.String())
		event.Reset()
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			if err := upstreamerror.FromEvent(strings.TrimSpace(strings.TrimPrefix(line, "data:"))); err != nil {
				return err
			}
		}
		event.WriteString(line)
		event.WriteByte('\n')
		if event.Len() > 1<<20 {
			return io.ErrShortBuffer
		}
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}
