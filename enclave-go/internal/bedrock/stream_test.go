package bedrock

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
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

func TestRelayEventSkipsMalformedRecord(t *testing.T) {
	var out bytes.Buffer
	for _, payload := range []string{
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`,
		`{"type":broken`, `{"type":""}`, `{"error":null,"choices":[broken`,
		`{"type":"message_stop"}`,
	} {
		if err := RelayEvent([]byte(payload), &out); err != nil {
			t.Fatalf("record interrupted stream: %v", err)
		}
	}
	if !strings.Contains(out.String(), "partial") || strings.Count(out.String(), "event: message_stop") != 1 {
		t.Fatalf("incomplete stream: %s", &out)
	}
}

// json.Compact is needed because the downstream adapter parses JSON per data
// line. Raw, pretty-printed AWS records otherwise silently lose their content.
func TestRelayEventCompactionPreservesDownstreamText(t *testing.T) {
	const payload = "{\"type\":\"content_block_delta\",\n\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}"
	const stop = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	raw, err := adapter.CollectAnthropicText(strings.NewReader("event: content_block_delta\ndata: " + payload + "\n\n" + stop))
	if err != nil || raw.Text != "" {
		t.Fatalf("raw multiline control changed: result=%+v err=%v", raw, err)
	}
	var out bytes.Buffer
	if err := RelayEvent([]byte(payload), &out); err != nil {
		t.Fatal(err)
	}
	out.WriteString(stop)
	result, err := adapter.CollectAnthropicText(&out)
	if err != nil || result.Text != "hello" {
		t.Fatalf("compacted record lost: result=%+v err=%v", result, err)
	}
}
