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
	var data []string
	flush := func() error {
		if event.Len() == 0 {
			return nil
		}
		if err := upstreamerror.FromEvent(strings.Join(data, "\n")); err != nil {
			return err
		}
		_, err := io.WriteString(w, event.String())
		event.Reset()
		data = nil
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
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
