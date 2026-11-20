package main

import "testing"

// TestOpenAIChatReasoningSwitchIsReasoningEffort pins what the OpenAI-style
// reasoning switch sends to first-party OpenAI chat completions. OpenAI has
// one reasoning control there, top-level reasoning_effort, and answers 400
// "Unknown parameter" to anything else. Reported 2026-11-19: reasoning
// {"enabled":true} on openai/gpt-5-nano and gpt-5-mini was sent the Claude
// thinking budget the shared projection writes for On, and OpenAI refused
// 'thinking'.
func TestOpenAIChatReasoningSwitchIsReasoningEffort(t *testing.T) {
	openai := func(upstream string) wireRoute {
		return wireRoute{kind: "chat", provider: "openai", model: "openai/" + upstream, upstream: upstream}
	}
	// gpt-5, gpt-5-mini and gpt-5-nano document minimal as their lowest
	// effort, the o-series low. Neither takes none.
	noOff := []wireRoute{openai("gpt-5-nano"), openai("gpt-5-mini"), openai("gpt-5"), openai("o4-mini")}
	// These document none.
	withOff := []wireRoute{openai("gpt-5.1"), openai("gpt-5.2"), openai("gpt-5.4-nano"), openai("gpt-5.5"), openai("gpt-5.5-2026-04-23")}
	type want struct{ noOff, withOff string }
	for _, tc := range []struct {
		fields string
		want   want
	}{
		{`"stream":false`, want{`{}`, `{}`}},
		// On alone is medium: OpenAI's documented default where a model
		// reasons by default, and On for models whose default is none.
		{`"reasoning":{"enabled":true}`, want{`{"reasoning_effort":"medium"}`, `{"reasoning_effort":"medium"}`}},
		{`"reasoning":{"enabled":true,"effort":"low"}`, want{`{"reasoning_effort":"low"}`, `{"reasoning_effort":"low"}`}},
		{`"reasoning":{"effort":"low"}`, want{`{"reasoning_effort":"low"}`, `{"reasoning_effort":"low"}`}},
		{`"reasoning_effort":"low"`, want{`{"reasoning_effort":"low"}`, `{"reasoning_effort":"low"}`}},
		{`"reasoning":{"enabled":true},"reasoning_effort":"high"`, want{`{"reasoning_effort":"high"}`, `{"reasoning_effort":"high"}`}},
		// The other switch spellings are the same request.
		{`"thinking":{"type":"enabled"}`, want{`{"reasoning_effort":"medium"}`, `{"reasoning_effort":"medium"}`}},
		{`"enable_thinking":true`, want{`{"reasoning_effort":"medium"}`, `{"reasoning_effort":"medium"}`}},
		{`"reasoning":true`, want{`{"reasoning_effort":"medium"}`, `{"reasoning_effort":"medium"}`}},
		// Off is effort none where the model documents it. Elsewhere the
		// route refuses it at preparation, as the Responses tool route does,
		// and the next candidate is tried.
		{`"reasoning":{"enabled":false}`, want{"route 400", `{"reasoning_effort":"none"}`}},
		{`"thinking":{"type":"disabled"}`, want{"route 400", `{"reasoning_effort":"none"}`}},
		{`"reasoning":false`, want{"route 400", `{"reasoning_effort":"none"}`}},
		{`"reasoning":{"effort":"none"}`, want{"route 400", `{"reasoning_effort":"none"}`}},
		{`"reasoning_effort":"none"`, want{"route 400", `{"reasoning_effort":"none"}`}},
		// Off governs an effort beside it.
		{`"reasoning":{"enabled":false,"effort":"high"}`, want{"route 400", `{"reasoning_effort":"none"}`}},
		{`"reasoning":{"enabled":false},"reasoning_effort":"high"`, want{"route 400", `{"reasoning_effort":"none"}`}},
		// OpenAI takes no thinking token budget.
		{`"reasoning":{"max_tokens":2048}`, want{"route 400", "route 400"}},
		{`"reasoning":{"enabled":true,"max_tokens":2048}`, want{"route 400", "route 400"}},
	} {
		for _, route := range noOff {
			if got := reasoningWire(t, route, tc.fields); got != tc.want.noOff {
				t.Errorf("%s %s:\n got %s\nwant %s", route.upstream, tc.fields, got, tc.want.noOff)
			}
		}
		for _, route := range withOff {
			if got := reasoningWire(t, route, tc.fields); got != tc.want.withOff {
				t.Errorf("%s %s:\n got %s\nwant %s", route.upstream, tc.fields, got, tc.want.withOff)
			}
		}
	}
}

// TestOpenAIToolRouteSwitchIsUnchanged keeps the Responses tool route as it
// was: it has its own projection of the switch (docs/reasoning-output.md,
// "OpenAI models that use tools"), which never carried a thinking field.
func TestOpenAIToolRouteSwitchIsUnchanged(t *testing.T) {
	route := wireRoute{kind: "chat", provider: "openai", model: "openai/gpt-5.5", upstream: "gpt-5.5", tools: true}
	if got := reasoningWire(t, route, `"reasoning":{"enabled":true}`); got != `{"reasoning":{"summary":"auto"}}` {
		t.Fatalf("Responses tool route On: %s", got)
	}
	if got := reasoningWire(t, route, `"reasoning":{"enabled":false}`); got != `{"reasoning":{"effort":"none"}}` {
		t.Fatalf("Responses tool route Off: %s", got)
	}
}
