package adapter

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// oneHourCacheStream is a native Anthropic stream whose message_start and
// message_delta carry the given usage objects verbatim.
func oneHourCacheStream(startUsage, deltaUsage string) string {
	return fmt.Sprintf(`event: message_start
data: {"type":"message_start","message":{"id":"msg_1h","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5","stop_reason":null,"usage":%s}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":%s}

event: message_stop
data: {"type":"message_stop"}

`, startUsage, deltaUsage)
}

// Anthropic's own usage shapes: 2000 cache-write tokens, 800 of them written
// with the one-hour lifetime.
const (
	startUsageWithBreakdown = `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"cache_creation":{"ephemeral_5m_input_tokens":1200,"ephemeral_1h_input_tokens":800},"output_tokens":1,"service_tier":"standard"}`
	startUsageNoBreakdown   = `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"output_tokens":1,"service_tier":"standard"}`
	deltaUsageNoBreakdown   = `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"output_tokens":6}`
	deltaUsageWithBreakdown = `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"cache_creation":{"ephemeral_5m_input_tokens":1200,"ephemeral_1h_input_tokens":800},"output_tokens":6}`
)

// oneHourCachePaths are the four entry points that call the usage parser, with
// whether the path writes the provider's own bytes to the client.
var oneHourCachePaths = []struct {
	name  string
	relay bool
	run   func(stream string) (StreamResult, string, error)
}{
	{"chat stream", false, func(stream string) (StreamResult, string, error) {
		var out bytes.Buffer
		result, err := TransformStreamCaptureWithOptions(strings.NewReader(stream), &out, "id-1h", "claude-sonnet-4-5", true)
		return result, out.String(), err
	}},
	// The collector serves the non-streaming chat, Responses and Messages replies.
	{"non-streaming collector", false, func(stream string) (StreamResult, string, error) {
		result, err := CollectAnthropicText(strings.NewReader(stream))
		if err != nil {
			return result, "", err
		}
		var out bytes.Buffer
		if err := WriteChatCompletionResponse(&out, "id-1h", "claude-sonnet-4-5", result.Text, "", nil, 14, 6, result.Usage, 1, result.FinishReason); err != nil {
			return result, "", err
		}
		if err := WriteResponsesResponse(&out, "resp_1h", "claude-sonnet-4-5", result.Text, nil, result.FinishReason, 14, 6, result.Usage, 1, nil, nil); err != nil {
			return result, "", err
		}
		err = WriteMessagesResponse(&out, "msg_1h", "claude-sonnet-4-5", result, 14, 6)
		return result, out.String(), err
	}},
	// Production always passes a control to the Responses stream; without one
	// this path does not read message_start usage at all.
	{"responses stream", false, func(stream string) (StreamResult, string, error) {
		var out bytes.Buffer
		result, err := TransformResponsesStreamControlled(strings.NewReader(stream), &out, "resp_1h", "claude-sonnet-4-5", 14, nil, nil, nil, &StreamControl{ExposeResponsesUsage: true})
		return result, out.String(), err
	}},
	{"messages relay", true, func(stream string) (StreamResult, string, error) {
		var out bytes.Buffer
		result, err := RelayAnthropicStream(strings.NewReader(stream), &out, "msg_1h", "claude-sonnet-4-5")
		return result, out.String(), err
	}},
}

func TestOneHourCacheWritesAreReadFromTheNestedBreakdown(t *testing.T) {
	for _, tc := range []struct {
		name         string
		start, delta string
		want         int
	}{
		{"breakdown on message_start, none on message_delta", startUsageWithBreakdown, deltaUsageNoBreakdown, 800},
		{"breakdown only on message_delta", startUsageNoBreakdown, deltaUsageWithBreakdown, 800},
		{"breakdown on both", startUsageWithBreakdown, deltaUsageWithBreakdown, 800},
		{"no breakdown", startUsageNoBreakdown, deltaUsageNoBreakdown, 0},
		// Only five-minute writes: the breakdown is present and its one-hour part is 0.
		{"breakdown without one-hour writes", `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_creation":{"ephemeral_5m_input_tokens":2000,"ephemeral_1h_input_tokens":0},"output_tokens":1}`, deltaUsageNoBreakdown, 0},
		// A later zero does not clear a count already reported, as with the
		// neighbouring fields.
		{"zero on message_delta keeps the message_start count", startUsageWithBreakdown, `{"cache_creation_input_tokens":2000,"cache_creation":{"ephemeral_5m_input_tokens":2000,"ephemeral_1h_input_tokens":0},"output_tokens":6}`, 800},
		{"later non-zero count replaces the earlier one", startUsageWithBreakdown, `{"cache_creation_input_tokens":2000,"cache_creation":{"ephemeral_1h_input_tokens":900},"output_tokens":6}`, 900},
	} {
		for _, path := range oneHourCachePaths {
			t.Run(tc.name+"/"+path.name, func(t *testing.T) {
				result, out, err := path.run(oneHourCacheStream(tc.start, tc.delta))
				if err != nil {
					t.Fatal(err)
				}
				if result.Usage == nil {
					t.Fatal("no usage")
				}
				if got := result.Usage.CacheCreation1hInputTokens; got != tc.want {
					t.Fatalf("CacheCreation1hInputTokens = %d, want %d", got, tc.want)
				}
				// The neighbouring counts are read exactly as before.
				if u := result.Usage; u.InputTokens != 14 || u.OutputTokens != 6 || u.CacheReadInputTokens != 6081 || u.CacheCreationInputTokens != 2000 || !u.InputExcludesCache {
					t.Fatalf("usage = %+v", *u)
				}
				assertOneHourCountNotAddedToOutput(t, path.relay, out)
			})
		}
	}
}

// assertOneHourCountNotAddedToOutput checks that the gateway writes no
// one-hour count of its own. The Messages relay forwards the provider's bytes,
// nested breakdown included; every other path builds its usage from named
// fields and so carries neither.
func assertOneHourCountNotAddedToOutput(t *testing.T, relay bool, out string) {
	t.Helper()
	if strings.Contains(out, "cache_creation_1h") || strings.Contains(out, "CacheCreation1h") {
		t.Fatalf("one-hour count added to public output: %s", out)
	}
	if !relay && strings.Contains(out, "ephemeral_1h_input_tokens") {
		t.Fatalf("nested breakdown reached translated output: %s", out)
	}
}

func TestOneHourCacheWritesIgnoreMalformedBreakdown(t *testing.T) {
	for _, tc := range []struct {
		name      string
		breakdown string
	}{
		{"null", `null`},
		{"number", `800`},
		{"string", `"800"`},
		{"array", `[800]`},
		{"boolean", `true`},
		{"empty object", `{}`},
		{"other lifetime only", `{"ephemeral_5m_input_tokens":800}`},
		{"string count", `{"ephemeral_1h_input_tokens":"800"}`},
		{"null count", `{"ephemeral_1h_input_tokens":null}`},
		{"object count", `{"ephemeral_1h_input_tokens":{"tokens":800}}`},
		{"array count", `{"ephemeral_1h_input_tokens":[800]}`},
		{"boolean count", `{"ephemeral_1h_input_tokens":true}`},
		{"negative count", `{"ephemeral_1h_input_tokens":-800}`},
	} {
		start := `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_read_input_tokens":6081,"cache_creation":` + tc.breakdown + `,"output_tokens":1}`
		delta := `{"cache_creation":` + tc.breakdown + `,"output_tokens":6}`
		for _, path := range oneHourCachePaths {
			t.Run(tc.name+"/"+path.name, func(t *testing.T) {
				result, _, err := path.run(oneHourCacheStream(start, delta))
				if err != nil {
					t.Fatal(err)
				}
				if result.Usage == nil || result.Usage.CacheCreation1hInputTokens != 0 {
					t.Fatalf("usage = %+v, want no one-hour count", result.Usage)
				}
				// The malformed breakdown changes nothing else.
				if u := result.Usage; u.InputTokens != 14 || u.OutputTokens != 6 || u.CacheReadInputTokens != 6081 || u.CacheCreationInputTokens != 2000 || !u.InputExcludesCache {
					t.Fatalf("usage = %+v", *u)
				}
			})
		}
	}
}

// A fractional count is read the way the neighbouring counts read one: the
// shared helper truncates it.
func TestOneHourCacheWritesReadFractionLikeNeighbouringCounts(t *testing.T) {
	var usage *StreamUsage
	mergeUsage(&usage, map[string]any{"cache_creation_input_tokens": 2000.9, "cache_creation": map[string]any{"ephemeral_1h_input_tokens": 800.9}})
	if usage == nil || usage.CacheCreationInputTokens != 2000 || usage.CacheCreation1hInputTokens != 800 {
		t.Fatalf("usage = %+v", usage)
	}
}

// The adapter stores the count as reported, even above the total; the single
// bound is where it is copied into the settle usage (applyCacheUsage).
func TestOneHourCacheWritesAreStoredAsReported(t *testing.T) {
	start := `{"input_tokens":14,"cache_creation_input_tokens":2000,"cache_creation":{"ephemeral_1h_input_tokens":3000},"output_tokens":1}`
	for _, path := range oneHourCachePaths {
		t.Run(path.name, func(t *testing.T) {
			result, _, err := path.run(oneHourCacheStream(start, `{"output_tokens":6}`))
			if err != nil {
				t.Fatal(err)
			}
			if result.Usage == nil || result.Usage.CacheCreation1hInputTokens != 3000 || result.Usage.CacheCreationInputTokens != 2000 {
				t.Fatalf("usage = %+v", result.Usage)
			}
		})
	}
}

// A breakdown alone is not usage: with every other count zero the object is
// still treated as empty, exactly as it was before the breakdown was read.
func TestOneHourBreakdownAloneIsNotUsage(t *testing.T) {
	var usage *StreamUsage
	mergeUsage(&usage, map[string]any{"cache_creation": map[string]any{"ephemeral_1h_input_tokens": float64(800)}})
	if usage != nil {
		t.Fatalf("usage = %+v, want none", usage)
	}
	// On an existing usage it is kept, and bounded later at the copy.
	usage = &StreamUsage{InputTokens: 3}
	mergeUsage(&usage, map[string]any{"output_tokens": float64(2), "cache_creation": map[string]any{"ephemeral_1h_input_tokens": float64(800)}})
	if usage.CacheCreation1hInputTokens != 800 || usage.InputTokens != 3 || usage.OutputTokens != 2 {
		t.Fatalf("usage = %+v", usage)
	}
}

// The Messages relay forwards the provider's usage bytes unchanged, so the
// client still sees the provider's own nested breakdown.
func TestMessagesRelayForwardsProviderBreakdownUnchanged(t *testing.T) {
	var out bytes.Buffer
	stream := oneHourCacheStream(startUsageWithBreakdown, deltaUsageWithBreakdown)
	if _, err := RelayAnthropicStream(strings.NewReader(stream), &out, "msg_1h", "claude-sonnet-4-5"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), `"cache_creation":{"ephemeral_5m_input_tokens":1200,"ephemeral_1h_input_tokens":800}`); got != 2 {
		t.Fatalf("provider breakdown relayed %d times, want 2: %s", got, out.String())
	}
}
