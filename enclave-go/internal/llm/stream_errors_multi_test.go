//go:build llm_multi

package llm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestGeminiStreamErrorEvents(t *testing.T) {
	const event = "data: {\"error\":{\"code\":403,\"message\":\"Safety policy\",\"status\":\"PERMISSION_DENIED\"}}\n\n"
	const content = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"partial\",\"type\":\"text_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n\n"
	for _, prefix := range []string{"", "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n\n"} {
		var out bytes.Buffer
		err := translateGeminiStreamToAnthropic(strings.NewReader(prefix+event), &out)
		d := upstreamerror.Parse(err)
		want := ""
		if prefix != "" {
			want = content
		}
		if err == nil || d.Status != 403 || d.Message != "Safety policy" || d.Type != "PERMISSION_DENIED" || out.String() != want {
			t.Fatalf("error=%#v body=%q", d, out.String())
		}
	}
}

func TestChutesCountingWriterForwardsOpen(t *testing.T) {
	out := &streamOpenTestWriter{}
	counted := &byteCountingWriter{writer: out}
	if !upstreamerror.Open(counted) || !out.opened || !counted.opened || counted.bytes != 0 {
		t.Fatalf("opened=%t downstream=%t bytes=%d", counted.opened, out.opened, counted.bytes)
	}
	var buffered bytes.Buffer
	counted = &byteCountingWriter{writer: &buffered}
	if upstreamerror.Open(counted) || counted.opened {
		t.Fatal("buffered invocation must retain pre-output retry")
	}
}
