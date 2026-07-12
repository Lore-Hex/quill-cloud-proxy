package types

import (
	"strings"
	"testing"
)

func TestValidateAttributionNormalizesRefererHost(t *testing.T) {
	req := &OpenAIChatRequest{
		User:          "user-123",
		SessionID:     "matter-456",
		HTTPReferer:   "https://legal.example/review",
		AppCategories: []string{"legal", "productivity"},
		Trace:         map[string]any{"source": "eval"},
	}
	if err := req.ValidateAttribution(); err != nil {
		t.Fatalf("ValidateAttribution: %v", err)
	}
	if req.App != "legal.example" {
		t.Fatalf("app = %q", req.App)
	}
}

func TestValidateAttributionRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name string
		req  *OpenAIChatRequest
		want string
	}{
		{name: "user", req: &OpenAIChatRequest{User: strings.Repeat("u", 257)}, want: "user"},
		{name: "session", req: &OpenAIChatRequest{SessionID: strings.Repeat("s", 257)}, want: "session_id"},
		{name: "referer scheme", req: &OpenAIChatRequest{HTTPReferer: "file:///etc/passwd"}, want: "http or https"},
		{name: "categories count", req: &OpenAIChatRequest{AppCategories: []string{"one", "two", "three"}}, want: "at most 2"},
		{name: "category shape", req: &OpenAIChatRequest{AppCategories: []string{"Legal Ops"}}, want: "lowercase kebab-case"},
		{name: "trace bytes", req: &OpenAIChatRequest{Trace: map[string]any{"value": strings.Repeat("x", 8192)}}, want: "8192"},
		{name: "trace items", req: &OpenAIChatRequest{Trace: map[string]any{"values": make([]any, 257)}}, want: "256"},
		{name: "trace depth", req: &OpenAIChatRequest{Trace: nestedTrace(9)}, want: "8 levels"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.req.ValidateAttribution()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func nestedTrace(depth int) map[string]any {
	var value any = "leaf"
	for range depth {
		value = map[string]any{"next": value}
	}
	return value.(map[string]any)
}
