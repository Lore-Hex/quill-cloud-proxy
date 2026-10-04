package bedrock

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestRelayEventRejectsProviderErrors(t *testing.T) {
	for _, payload := range []string{
		"{\"type\":\"error\",\n\"error\":{\"message\":\"refused\"}}",
		`{"type":"error","error":{"code":` + strings.Repeat("9", 1500) + `}}`,
		`{"type":"error","error":{"code":NaN}}`,
	} {
		var out bytes.Buffer
		err := RelayEvent([]byte(payload), &out)
		if err == nil || upstreamerror.Parse(err).Status != 502 || out.Len() != 0 {
			t.Fatalf("error forwarded as content: %v %s", err, out.String())
		}
	}
}

func TestRelayEventFramesMultilineJSON(t *testing.T) {
	var out bytes.Buffer
	if err := RelayEvent([]byte("{\"type\":\"content_block_delta\",\n\"delta\":{\"text\":\"hello\"}}"), &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
