//go:build llm_multi

package llm

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestProviderStreamsRejectMultilineErrors(t *testing.T) {
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	const partial = `{"choices":[{"delta":{"content":"partial"}}]}`
	cases := []struct {
		name, prefix string
		translate    func(io.Reader, io.Writer) error
	}{
		{"openai", "data: " + partial + "\n\n", translateOpenAIStreamToAnthropic},
		{"bedrock", "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n", relayBedrockTestEvents},
		{"anthropic", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n", relayAnthropicStream},
		{"gemini", "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n\n", translateGeminiStreamToAnthropic},
		{"vertex-strict", "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n\n", func(r io.Reader, w io.Writer) error { return translateGeminiStreamToAnthropicMode(r, w, true) }},
		{"responses", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n", translateOpenAIResponsesStream},
		{"chutes", strings.TrimSuffix(chutesTestEncryptedStreamWithTerminal(t, base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()), false, partial), "data: [DONE]\n\n"), func(r io.Reader, w io.Writer) error { return translateChutesEncryptedStream(r, w, key) }},
	}
	for _, tc := range cases {
		for _, end := range []struct{ name, wire string }{{"done", "\n\ndata: [DONE]\n\n"}, {"eof", ""}} {
			t.Run(tc.name+"/"+end.name, func(t *testing.T) {
				wire := tc.prefix + "event: error\ndata: {\"type\":\"error\",\n: keepalive\ndata: \"error\":{\"code\":403,\"message\":\"multiline refusal\"}}" + end.wire
				var out bytes.Buffer
				err := tc.translate(strings.NewReader(wire), &out)
				d := upstreamerror.Parse(err)
				wantStatus, wantMessage := 403, "multiline refusal"
				if tc.name == "openai" || tc.name == "gemini" || tc.name == "vertex-strict" {
					// Line readers fail closed on the first error-looking fragment.
					wantStatus, wantMessage = 502, `{"type":"error",`
				}
				if tc.name == "chutes" || (tc.name == "responses" && end.name == "eof") {
					// Chutes rejects the malformed encrypted envelope. Responses
					// does not dispatch an event without a terminating blank line.
					wantStatus, wantMessage = 502, "provider error"
				}
				if err == nil || d.Status != wantStatus || d.Message != wantMessage || !strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "message_stop") {
					t.Fatalf("multiline failure lost: err=%v detail=%+v output=%s", err, d, out.String())
				}
			})
		}
	}
}

func TestProviderStreamsRejectOversizedNumericErrors(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		translate    func(io.Reader, io.Writer) error
	}{
		{"openai", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", translateOpenAIStreamToAnthropic},
		{"anthropic", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"partial\"}}\n\n", relayAnthropicStream},
		{"gemini", "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n\n", translateGeminiStreamToAnthropic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			wire := tc.prefix + `data: {"error":{"message":"numeric refusal","code":` + strings.Repeat("9", 1500) + `}}` + "\n\ndata: [DONE]\n\n"
			err := tc.translate(strings.NewReader(wire), &out)
			d := upstreamerror.Parse(err)
			if err == nil || d.Status != 502 || d.Message != "numeric refusal" || d.Code != nil || !strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "message_stop") {
				t.Fatalf("numeric failure lost: err=%v detail=%+v output=%s", err, d, out.String())
			}
		})
	}
}

// Convert the common SSE fixture into complete JSON records, as the AWS SDK
// does for Bedrock's binary transport. Exercise the production record relay.
func relayBedrockTestEvents(r io.Reader, w io.Writer) error {
	wire, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	for _, block := range strings.Split(string(wire), "\n\n") {
		var data []string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(line, "data:"))
			}
		}
		payload := strings.TrimSpace(strings.Join(data, "\n"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if err := bedrock.RelayEvent([]byte(payload), w); err != nil {
			return err
		}
	}
	return nil
}
