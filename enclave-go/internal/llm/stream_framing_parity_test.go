//go:build llm_multi

package llm

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type framingProvider struct {
	name, content string
	line          bool
	translate     func(io.Reader, io.Writer) error
}

func framingProviders(t *testing.T) []framingProvider {
	t.Helper()
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	const openai = `{"choices":[{"delta":{"content":"partial"}}]}`
	const native = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"
	const gemini = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n"
	return []framingProvider{
		{"openai", "data: " + openai + "\n", true, translateOpenAIStreamToAnthropic},
		{"gemini", gemini, true, translateGeminiStreamToAnthropic},
		{"vertex", gemini, true, func(r io.Reader, w io.Writer) error { return translateGeminiStreamToAnthropicMode(r, w, true) }},
		// Observe the encrypted reader directly; the downstream translator
		// runs in a separate goroutine and has its own delivery barrier above.
		{"chutes", strings.ReplaceAll(strings.TrimSuffix(chutesTestEncryptedStreamWithTerminal(t, base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()), false, openai), "data: [DONE]\n\n"), "\n\n", "\n"), true, func(r io.Reader, w io.Writer) error { return decryptChutesStream(r, w, key) }},
		{"responses", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n", false, translateOpenAIResponsesStream},
		{"anthropic", native, false, relayAnthropicStream},
		{"bedrock", native, false, relayBedrockTestEvents},
	}
}

type deliveryBarrier struct {
	io.Reader
	output *bytes.Buffer
	reads  int
}

func (r *deliveryBarrier) Read(p []byte) (int, error) {
	if r.reads > 0 && !strings.Contains(r.output.String(), "partial") {
		return 0, errors.New("requested next line before delivering content")
	}
	r.reads++
	return r.Reader.Read(p)
}

func TestProviderDeliveryBeforeNextLine(t *testing.T) {
	for _, tc := range framingProviders(t) {
		if tc.name == "bedrock" {
			continue
		} // AWS supplies complete records, not a byte reader.
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			go func() {
				defer pw.Close()
				io.WriteString(pw, tc.content)
				// This second write cannot be read until content was delivered;
				// the read barrier reports lookahead immediately, without a timer.
				io.WriteString(pw, "data: {\"error\":{\"code\":403}}\n\n")
			}()
			var out bytes.Buffer
			err := tc.translate(&deliveryBarrier{Reader: pr, output: &out}, &out)
			if !strings.Contains(out.String(), "partial") || upstreamerror.Parse(err).Status != 403 {
				t.Fatalf("content buffered: err=%v out=%s", err, out.String())
			}
		})
	}
}

func TestProviderSplitErrorAfterContent(t *testing.T) {
	for _, tc := range framingProviders(t) {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			wire := tc.content + "\nevent: error\ndata: {\"error\":\ndata: {\"code\":403,\"message\":\"refused\"}}\n\n"
			err := tc.translate(strings.NewReader(wire), &out)
			want := 403
			if tc.line {
				want = 502
			}
			if err == nil || upstreamerror.Parse(err).Status != want || !strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "message_stop") {
				t.Fatalf("split failure lost: err=%v out=%s", err, out.String())
			}
		})
	}
}

func TestOpenAISingleNewlineLongAndMalformed(t *testing.T) {
	const chunk = "data: {\"choices\":[{\"delta\":{\"content\":\"a content chunk long enough to exceed the stream size bound\"}}]}\n"
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "15000", true: "malformed"}[malformed], func(t *testing.T) {
			wire := strings.Repeat(chunk, 15000)
			want := 15000
			if malformed {
				wire = chunk + "data: {\"choices\":[broken\n" + chunk
				want = 2
			}
			wire += "data: [DONE]\n"
			var out bytes.Buffer
			err := translateOpenAIStreamToAnthropic(strings.NewReader(wire), &out)
			if err != nil || strings.Count(out.String(), "a content chunk") != want || strings.Count(out.String(), "event: message_stop") != 1 {
				t.Fatalf("lost later content/terminal: err=%v chunks=%d want=%d", err, strings.Count(out.String(), "a content chunk"), want)
			}
		})
	}
}

// Main's policy: non-strict Gemini skips a malformed chunk and keeps later
// content; strict Vertex fails on it.
func TestGeminiMalformedChunkPolicyMatchesMain(t *testing.T) {
	wire := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\ndata: {broken\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" later\"}]},\"finishReason\":\"STOP\"}]}\n"
	var out bytes.Buffer
	if err := translateGeminiStreamToAnthropic(strings.NewReader(wire), &out); err != nil || !strings.Contains(out.String(), "partial") || !strings.Contains(out.String(), " later") || !strings.Contains(out.String(), "message_stop") {
		t.Fatalf("non-strict Gemini did not skip the malformed chunk: err=%v out=%s", err, out.String())
	}
	out.Reset()
	if err := translateGeminiStreamToAnthropicMode(strings.NewReader(wire), &out, true); err == nil || !strings.Contains(err.Error(), "malformed event") {
		t.Fatalf("strict Vertex accepted a malformed chunk: err=%v out=%s", err, out.String())
	}
}

func TestChutesDecryptedFramingMatchesMain(t *testing.T) {
	for _, wire := range []string{"data: {}\ndata: []", "data: {\ndata: \"choices\":[]}"} {
		if _, _, err := frameChutesDecryptedChunk([]byte(wire)); err == nil {
			t.Fatalf("accepted multiple data lines in one decrypted chunk: %s", wire)
		}
	}
}
