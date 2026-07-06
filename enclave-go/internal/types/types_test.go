package types

import (
	"encoding/json"
	"testing"
)

func TestProviderRoutingAcceptsArrayAndCommaSeparatedString(t *testing.T) {
	var req OpenAIChatRequest
	if err := json.Unmarshal(
		[]byte(`{"model":"trustedrouter/zdr","messages":[],"provider":{"only":"google-vertex, anthropic","order":["openai","gemini"]}}`),
		&req,
	); err != nil {
		t.Fatalf("unmarshal chat request: %v", err)
	}
	if req.Provider == nil {
		t.Fatal("provider routing was nil")
	}
	if got, want := []string(req.Provider.Only), []string{"google-vertex", "anthropic"}; !equalStrings(got, want) {
		t.Fatalf("only = %#v, want %#v", got, want)
	}
	if got, want := []string(req.Provider.Order), []string{"openai", "gemini"}; !equalStrings(got, want) {
		t.Fatalf("order = %#v, want %#v", got, want)
	}
}

func TestOpenAIChatRequestNormalizeMaxTokens(t *testing.T) {
	tests := []struct {
		name string
		body string
		want *int
	}{
		{
			name: "max_completion_tokens only",
			body: `{"model":"m","messages":[],"max_completion_tokens":123}`,
			want: intPtr(123),
		},
		{
			name: "max_output_tokens only",
			body: `{"model":"m","messages":[],"max_output_tokens":234}`,
			want: intPtr(234),
		},
		{
			name: "max_tokens only",
			body: `{"model":"m","messages":[],"max_tokens":345}`,
			want: intPtr(345),
		},
		{
			name: "max_tokens wins over max_completion_tokens",
			body: `{"model":"m","messages":[],"max_tokens":456,"max_completion_tokens":567}`,
			want: intPtr(456),
		},
		{
			name: "max_completion_tokens wins over max_output_tokens",
			body: `{"model":"m","messages":[],"max_completion_tokens":678,"max_output_tokens":789}`,
			want: intPtr(678),
		},
		{
			name: "none",
			body: `{"model":"m","messages":[]}`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req OpenAIChatRequest
			if err := json.Unmarshal([]byte(tt.body), &req); err != nil {
				t.Fatalf("unmarshal chat request: %v", err)
			}
			req.NormalizeMaxTokens()
			if tt.want == nil {
				if req.MaxTokens != nil {
					t.Fatalf("MaxTokens = %d, want nil", *req.MaxTokens)
				}
				return
			}
			if req.MaxTokens == nil || *req.MaxTokens != *tt.want {
				t.Fatalf("MaxTokens = %v, want %d", req.MaxTokens, *tt.want)
			}
		})
	}
}

func TestOpenAIChatRequestStopSequences(t *testing.T) {
	tests := []struct {
		name string
		stop any
		want []string
	}{
		{name: "nil", stop: nil, want: nil},
		{name: "string", stop: "END", want: []string{"END"}},
		{name: "strings", stop: []string{"A", "B"}, want: []string{"A", "B"}},
		{name: "any strings only", stop: []any{"A", float64(1), "B", nil}, want: []string{"A", "B"}},
		{name: "unsupported", stop: float64(1), want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &OpenAIChatRequest{Stop: tt.stop}
			if got := req.StopSequences(); !equalStrings(got, tt.want) {
				t.Fatalf("StopSequences() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intPtr(i int) *int {
	return &i
}
