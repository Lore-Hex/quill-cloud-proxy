package llm

import (
	"bytes"
	"strings"
	"testing"
)

func TestMalformedContentKeepsProviderPolicy(t *testing.T) {
	for _, provider := range []string{"openai", "privatemode", "tencent"} {
		for _, malformed := range []struct{ name, data string }{
			{"malformed", `{"choices":[broken`},
			{"null_error", `{"error":null,"choices":[broken`},
			{"concatenated", `{"choices":[]} {"choices":[]}`},
		} {
			t.Run(provider+"/"+malformed.name, func(t *testing.T) {
				wire := "data: {\"choices\":[{\"delta\":{\"content\":\"before\"}}]}\n\n" +
					"data: " + malformed.data + "\n\n" +
					"data: {\"choices\":[{\"delta\":{\"content\":\"after\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
				var out bytes.Buffer
				err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(wire), &out, provider)
				if provider != "openai" {
					if err == nil || strings.Contains(out.String(), "message_stop") {
						t.Fatalf("strict provider accepted malformed content: err=%v output=%s", err, out.String())
					}
					return
				}
				if err != nil || !strings.Contains(out.String(), `"text":"before"`) ||
					!strings.Contains(out.String(), `"text":"after"`) || !strings.Contains(out.String(), "message_stop") {
					t.Fatalf("non-error chunk interrupted the stream: err=%v output=%s", err, out.String())
				}
			})
		}
	}
}
