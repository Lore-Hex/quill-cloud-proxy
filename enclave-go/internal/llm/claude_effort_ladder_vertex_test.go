//go:build llm_vertex || llm_multi

package llm

import "testing"

// The Vertex wire is built from the same dispatched body as the direct wire,
// so a Vertex model ID gets its class's ladder and the same clean request.
func TestClaudeEffortLadderOnTheVertexWire(t *testing.T) {
	for _, tc := range []struct{ id, fields, want string }{
		{"claude-sonnet-4-5@20250929", `"reasoning_effort":"max","temperature":0.2,"top_k":40,"top_p":0.5`,
			`{"max_tokens":12288,"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-sonnet-4-5@20250929", `"reasoning":{"enabled":false},"reasoning_effort":"high","temperature":0.2`,
			`{"max_tokens":4096,"temperature":0.2}`},
		{"claude-haiku-4-5@20251001", `"reasoning_effort":"high","top_p":0.97,"tool_choice":"required",` + claudeTestTools,
			`{"max_tokens":4096,"tool_choice":{"type":"any"},"top_p":0.97}`},
		{"claude-opus-4-5@20251101", `"reasoning_effort":"max","top_k":40`,
			`{"max_tokens":12288,"output_config":{"effort":"high"},"thinking":{"budget_tokens":8192,"type":"enabled"}}`},
		{"claude-sonnet-4-6@20260217", `"reasoning_effort":"xhigh"`,
			`{"max_tokens":32000,"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`},
		{"claude-haiku-5-5@20261001", `"reasoning_effort":"minimal"`,
			`{"max_tokens":32000,"output_config":{"effort":"low"},"thinking":{"type":"adaptive"}}`},
		{"claude-sonnet-5-5@20261001", `"reasoning":{"enabled":false},"reasoning_effort":"high"`,
			`{"max_tokens":4096,"thinking":{"type":"between_tools"}}`},
		{"claude-opus-4-8@20260115", `"reasoning":{"enabled":true},"top_p":0.5,"top_k":40`,
			`{"max_tokens":32000,"thinking":{"type":"adaptive"},"top_k":40}`},
		{"claude-haiku-5-5@20261001", `"reasoning":true`,
			`{"max_tokens":32000,"thinking":{"type":"adaptive"}}`},
		{"claude-sonnet-4-6@20260217", `"reasoning":{"enabled":true}`,
			`{"max_tokens":8192,"thinking":{"budget_tokens":4096,"type":"enabled"}}`},
		{"claude-opus-4-8@20260115", `"reasoning":{"enabled":true,"max_tokens":2048}`,
			`{"max_tokens":4096,"thinking":{"budget_tokens":2048,"type":"enabled"}}`},
	} {
		req, body := claudeChat(t, tc.fields)
		native := anthropicChatReasoningBody(tc.id, req, body)
		wire := buildVertexAnthropicWireRequest(tc.id, native.Messages, native)
		if got := claudeControls(t, wire, "thinking", "output_config", "max_tokens", "temperature", "top_p", "top_k", "tool_choice"); got != tc.want {
			t.Errorf("%s %s:\n got %s\nwant %s", tc.id, tc.fields, got, tc.want)
		}
	}
}
