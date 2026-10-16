package transcription

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// Optional raw fixture captured from the real OpenAI Python SDK's mock
// transport. It contains generated audio and no live credential.
func TestOpenAISDKMultipart(t *testing.T) {
	path := os.Getenv("TR_TRANSCRIPTION_SDK_FIXTURE")
	if path == "" {
		t.Skip("SDK-generated multipart fixture not supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header, raw, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		t.Fatal("missing fixture content type")
	}
	req, err := Parse(raw, strings.TrimPrefix(string(header), "Content-Type: "))
	if err != nil {
		t.Fatal(err)
	}
	if err := Measure(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if req.Model != "openai/whisper-large-v3-turbo" || req.Provider == nil || req.Provider.MinPrivacy != "confidential" || len(req.Provider.Only) != 1 || req.Provider.Only[0] != "tinfoil" {
		t.Fatal("SDK routing settings not preserved")
	}
}
