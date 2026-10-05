package llm

import (
	"bufio"
	"io"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// Native Anthropic events pass through unchanged after complete-block validation.
func relayAnthropicStream(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), adapter.MaxSSEBlockBytes)
	scanner.Split(adapter.SplitDoubleNewline)
	for scanner.Scan() {
		block := scanner.Bytes()
		name, data := adapter.ParseSSEBlock(block)
		if err := upstreamerror.CheckEvent(name, strings.Join(data, "\n")); err != nil {
			return err
		}
		if _, err := io.WriteString(w, string(block)+"\n\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}
