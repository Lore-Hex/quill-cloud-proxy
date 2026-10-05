package llm

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestMainParityOpenAIFraming(t *testing.T) {
	const content = "data: {\"choices\":[{\"delta\":{\"content\":\"later\"}}]}\n"
	for _, provider := range []string{"openai", "privatemode", "tencent"} {
		for _, tc := range []struct {
			name, prefix  string
			strictFailure bool
		}{
			{"done_space", "data: [DONE] \n", true},
			{"no_space", "data:{\"choices\":[{\"delta\":{\"content\":\"ignored\"}}]}\n", false},
			{"empty", "data: \n", true},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				var out bytes.Buffer
				err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(tc.prefix+content+"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\ndata: [DONE]\n"), &out, provider)
				if tc.strictFailure && provider != "openai" {
					if err == nil || !strings.Contains(err.Error(), "malformed") || strings.Contains(out.String(), "later") || strings.Contains(out.String(), "message_stop") {
						t.Fatalf("strict framing: err=%v out=%s", err, &out)
					}
					return
				}
				if err != nil || !strings.Contains(out.String(), "later") || strings.Contains(out.String(), "ignored") || !strings.Contains(out.String(), "message_stop") {
					t.Fatalf("framing: err=%v out=%s", err, &out)
				}
			})
		}
	}
}

func TestMainParityTencentErrorPrivacy(t *testing.T) {
	for _, payload := range []string{`{"error":{"code":403,"message":"PRIVATE PROMPT"}}`, `{"choices":[{"delta":{"error":"PRIVATE PROMPT"}}]}`} {
		var out bytes.Buffer
		err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader("data: "+payload+"\n"), &out, "tencent")
		detail := upstreamerror.Parse(err)
		if err == nil || detail.Status != 502 || detail.Message != "Tencent TokenHub stream failed" || strings.Contains(fmt.Sprint(err, detail), "PRIVATE") || out.Len() != 0 {
			t.Fatalf("Tencent failure leaked: err=%v detail=%+v", err, detail)
		}
	}
}

func TestMainParityChutesAuthenticatedTextCompletes(t *testing.T) {
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	const text = `The API returns {"error":"bad"} on failure.`
	wire := chutesTestEncryptedStream(t, base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()), text, `{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2}}`)
	pr, pw := io.Pipe()
	defer pr.Close()
	done := make(chan error, 1)
	go func() {
		err := translateChutesEncryptedStream(strings.NewReader(wire), pw, key)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	var out bytes.Buffer
	settlements := 0
	result, err := adapter.RelayAnthropicStreamWithTerminalHook(pr, &out, "msg", "model", func(adapter.StreamTerminal) error { settlements++; return nil })
	_ = pr.Close()
	providerErr := <-done
	encoded, _ := json.Marshal(text)
	if err != nil || providerErr != nil || settlements != 1 || result.Usage == nil || result.Usage.InputTokens != 5 || !bytes.Contains(out.Bytes(), encoded) || !strings.Contains(out.String(), "message_stop") {
		t.Fatalf("authenticated text failed: err=%v provider=%v settlements=%d result=%+v", err, providerErr, settlements, result)
	}
}

func TestMainParityNativeLargeDelta(t *testing.T) {
	text := strings.Repeat("x", 1100000)
	wire := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + text + "\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	var out bytes.Buffer
	if err := relayAnthropicStream(strings.NewReader(wire), &out); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.CollectAnthropicText(&out)
	if err != nil || result.Text != text {
		t.Fatalf("large delta: err=%v text bytes=%d", err, len(result.Text))
	}
}

func TestMainParityResponsesFraming(t *testing.T) {
	const content = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"
	const terminal = "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":2,\"total_tokens\":7}}}"
	for _, tc := range []struct{ name, wire, want string }{
		{"EOF", content + terminal, "stream ended without terminal usage"},
		{"empty", content + "data: \n\n" + terminal + "\n\n", "malformed event"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := translateOpenAIResponsesStream(strings.NewReader(tc.wire), &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "message_stop") {
				t.Fatalf("Responses framing: err=%v out=%s", err, &out)
			}
		})
	}
}
