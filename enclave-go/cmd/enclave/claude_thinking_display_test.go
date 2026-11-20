package main

import "testing"

// TestClaudeAdaptiveThinkingIsShown pins that a chat reasoning request the
// gateway turns into adaptive thinking asks for the thinking text back.
// Anthropic's default display on every model since Opus 4.7 (the full class:
// Opus 4.7, 4.8, 5 and 5.5, Sonnet 5 and 5.5, Haiku 5.5, Fable, Mythos) is
// "omitted", which streams thinking blocks with empty text. Observed
// 2026-11-19: reasoning {"enabled":true} on Haiku 5.5 and Sonnet 5.5 streamed
// no reasoning while Haiku 4.5, a budget model, did. Display changes what is
// returned, not what is thought or billed.
func TestClaudeAdaptiveThinkingIsShown(t *testing.T) {
	const shown = `"thinking":{"display":"summarized","type":"adaptive"}`
	for _, upstream := range []string{"claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-4-7", "claude-sonnet-5", "claude-fable-5-1", "us.anthropic.claude-haiku-5-5", "claude-haiku-5-5@20261001"} {
		route := wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/" + upstream, upstream: upstream}
		for fields, want := range map[string]string{
			`"reasoning":{"enabled":true}`:                `{` + shown + `}`,
			`"reasoning":{"effort":"high"}`:               `{"output_config":{"effort":"high"},` + shown + `}`,
			`"reasoning":{"enabled":true,"effort":"low"}`: `{"output_config":{"effort":"low"},` + shown + `}`,
			`"reasoning_effort":"medium"`:                 `{"output_config":{"effort":"medium"},` + shown + `}`,
			// Excluded reasoning is not returned to the caller, so it is not
			// asked for.
			`"reasoning":{"enabled":true,"exclude":true}`:         `{"thinking":{"type":"adaptive"}}`,
			`"reasoning_effort":"high","include_reasoning":false`: `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}`,
		} {
			if got := reasoningWire(t, route, fields); got != want {
				t.Errorf("%s %s:\n got %s\nwant %s", upstream, fields, got, want)
			}
		}
	}
	// The 4.6 models already return summarized thinking by default and are
	// sent the object as before.
	for _, upstream := range []string{"claude-sonnet-4-6", "claude-opus-4-6"} {
		route := wireRoute{kind: "claude", provider: "anthropic", model: "anthropic/" + upstream, upstream: upstream}
		if got := reasoningWire(t, route, `"reasoning_effort":"high"`); got != `{"output_config":{"effort":"high"},"thinking":{"type":"adaptive"}}` {
			t.Errorf("%s: %s", upstream, got)
		}
	}
}
