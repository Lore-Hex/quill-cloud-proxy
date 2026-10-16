package transcription_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/transcription"
)

func TestTinfoilVoxtralAdapterLive(t *testing.T) {
	if os.Getenv("TR_CONFIDENTIAL_MEDIA_LIVE") != "1" {
		t.Skip("paid synthetic audio opt-in")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	raw, _ := json.Marshal(map[string]any{"model": "mistralai/voxtral-small-24b", "input_audio": map[string]string{"data": base64.StdEncoding.EncodeToString(parisAudio), "format": "wav"}})
	req, err := transcription.Parse(raw, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if err := transcription.Measure(ctx, req); err != nil {
		t.Fatal(err)
	}
	c := transcription.New(http.DefaultClient, map[string]string{"tinfoil": os.Getenv("TINFOIL_API_KEY")}, llm.TinfoilAttestedHTTPClient)
	out, err := c.Transcribe(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	text, ok := out["text"].(string)
	if !ok || !strings.Contains(strings.ToLower(text), "paris") {
		t.Fatal("synthetic transcript mismatch")
	}
	usage, err := transcription.TakeTokenUsage(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified transcript and exact usage input=%d output=%d", usage.Input, usage.Output)
}
