//go:build llm_multi

package llm

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestLineReadersDetectSplitErrorTokens(t *testing.T) {
	for _, provider := range []struct {
		name, good string
		translate  func(io.Reader, io.Writer) error
	}{
		{"openai", `{"choices":[{"delta":{"content":"healthy"}}]}`, translateOpenAIStreamToAnthropic},
		{"gemini", `{"candidates":[{"content":{"parts":[{"text":"healthy"}]}}]}`, translateGeminiStreamToAnthropic},
	} {
		good := "data: " + provider.good + "\n"
		for _, tc := range []struct {
			name, wire string
			failure    bool
		}{
			{"scalar error key", "data: {\ndata: \"error\"\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
			{"scalar key with comment", "data: {\ndata: \"error\"\n: keepalive\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
			{"scalar key with field", "data: {\ndata: \"error\"\nid: 42\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
			{"padded error key", "data: {\ndata: \"error\"" + strings.Repeat(" ", 100) + "\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
			{"scalar type key", "data: {\ndata: \"type\"\ndata: :\"error\"}\n", true},
			{"scalar null error", "data: {\ndata: \"error\"\ndata: : null}\n", false},
			{"before colon", "data: {\"error\"\ndata: :{\"code\":403,\"message\":\"denied\"}}\n", true},
			{"empty data", "data: {\"error\"\ndata: \ndata: :{\"code\":403,\"message\":\"denied\"}}\n", true},
			{"bare empty data", "data: {\"error\"\ndata:\ndata: :{\"code\":403,\"message\":\"denied\"}}\n", true},
			{"many empty data", "data: {\"error\"\n" + strings.Repeat("data: \n", 100) + "data: :{\"code\":403,\"message\":\"denied\"}}\n", true},
			{"type before colon", "data: {\"type\"\ndata: :\"error\",\"message\":\"denied\"}\n", true},
			{"type before value", "data: {\"type\"\ndata: :\ndata: \"error\",\"message\":\"denied\"}\n", true},
			{"error before value", "data: {\"error\":\ndata: {\"code\":403,\"message\":\"denied\"}}\n", true},
			{"split null", "data: {\"error\"\ndata: : null,\"choices\":[]}\n", false},
			{"good resets tail", "data: {\"error\"\n" + good + "data: :{\"message\":\"denied\"}}\n", false},
			{"comment preserves tail", "data: {\"error\"\n: keepalive\ndata: :{\"message\":\"denied\"}}\n", true},
			{"blank resets tail", "data: {\"error\"\n\ndata: :{\"message\":\"denied\"}}\n", false},
			{"malformed content", "data: {broken\n" + good + "data: [broken\n", false},
		} {
			t.Run(provider.name+"/"+tc.name, func(t *testing.T) {
				var got, want bytes.Buffer
				err := provider.translate(strings.NewReader(good+tc.wire+good+"data: [DONE]\n"), &got)
				if tc.failure {
					if err == nil || !strings.Contains(got.String(), "healthy") || strings.Contains(got.String(), "message_stop") {
						t.Fatalf("split report completed: err=%v out=%s", err, &got)
					}
					return
				}
				count := 2
				if strings.Contains(tc.wire, good) {
					count++
				}
				if wantErr := provider.translate(strings.NewReader(strings.Repeat(good, count)+"data: [DONE]\n"), &want); err != nil || wantErr != nil || got.String() != want.String() {
					t.Fatalf("healthy stream changed: err=%v out=%s want=%s", err, &got, &want)
				}
			})
		}
	}
}
