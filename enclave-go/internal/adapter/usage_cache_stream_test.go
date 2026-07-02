package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// cacheBearingAnthropicStream mirrors a native Anthropic cache HIT: message_start
// reports input_tokens EXCLUSIVE of cache (3) plus cache_read_input_tokens
// (6034), and message_delta carries the output count.
const cacheBearingAnthropicStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_02","type":"message","role":"assistant","content":[],"model":"claude-haiku-4-5","stop_reason":null,"usage":{"input_tokens":3,"cache_read_input_tokens":6034,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}

event: message_stop
data: {"type":"message_stop"}
`

// TestUsageChunkFoldsAnthropicCacheEndToEnd is the end-to-end guard: an Anthropic
// cache-read stream must yield a stream_options.include_usage chunk whose
// prompt_tokens is the FULL prompt (input 3 + cache_read 6034 = 6037) with
// prompt_tokens_details.cached_tokens=6034 — proving the message_start-based
// convention detection folds cache back into prompt_tokens for Anthropic.
func TestUsageChunkFoldsAnthropicCacheEndToEnd(t *testing.T) {
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(cacheBearingAnthropicStream), &out, "id1", "claude-haiku-4-5", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage == nil || !result.Usage.InputExcludesCache {
		t.Fatalf("expected InputExcludesCache=true from message_start usage: %#v", result.Usage)
	}
	if result.Usage.CacheReadInputTokens != 6034 {
		t.Fatalf("CacheReadInputTokens = %d, want 6034", result.Usage.CacheReadInputTokens)
	}

	blocks := strings.Split(strings.TrimSpace(out.String()), "\n\n")
	var chunk map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(blocks[len(blocks)-2], "data: ")), &chunk); err != nil {
		t.Fatalf("unmarshal usage chunk: %v", err)
	}
	usage := chunk["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(6037) {
		t.Fatalf("prompt_tokens = %v, want 6037", usage["prompt_tokens"])
	}
	if usage["total_tokens"] != float64(6047) {
		t.Fatalf("total_tokens = %v, want 6047", usage["total_tokens"])
	}
	details := usage["prompt_tokens_details"].(map[string]any)
	if details["cached_tokens"] != float64(6034) {
		t.Fatalf("cached_tokens = %v, want 6034", details["cached_tokens"])
	}
}

// TestRelayAnthropicStreamRecordsCacheConvention covers the native /v1/messages
// streaming relay: it must record the Anthropic cache convention on message_start
// (like the chat/non-streaming paths) so a full cache hit settles on the real
// input_tokens:0 rather than the chars/4 estimate.
func TestRelayAnthropicStreamRecordsCacheConvention(t *testing.T) {
	var out bytes.Buffer
	result, err := RelayAnthropicStream(strings.NewReader(cacheBearingAnthropicStream), &out, "msg_x", "claude-haiku-4-5")
	if err != nil {
		t.Fatalf("RelayAnthropicStream: %v", err)
	}
	if result.Usage == nil || !result.Usage.InputExcludesCache {
		t.Fatalf("expected InputExcludesCache=true for native /v1/messages relay: %#v", result.Usage)
	}
	if result.Usage.CacheReadInputTokens != 6034 {
		t.Fatalf("CacheReadInputTokens = %d, want 6034", result.Usage.CacheReadInputTokens)
	}
}

// TestResponsesUsageFoldsAnthropicFullCacheHit covers the /v1/responses builder:
// a non-streaming full cache hit passes real input_tokens:0 (realOrEstimatedTokens
// keeps the real zero) with cache_read>0, and WriteResponsesResponse must fold
// the cache into input_tokens/total_tokens so the client-facing usage is coherent
// (input_tokens:6034, total:6044, input_tokens_details.cached_tokens:6034) rather
// than input_tokens:0 with a positive cached_tokens.
func TestResponsesUsageFoldsAnthropicFullCacheHit(t *testing.T) {
	var out bytes.Buffer
	err := WriteResponsesResponse(
		&out, "resp_test", "anthropic/claude-haiku-4.5", "ok", nil,
		0,  // real uncached input_tokens for a full cache hit
		10, // output
		&StreamUsage{OutputTokens: 10, CacheReadInputTokens: 6034, InputExcludesCache: true},
		123, nil, nil,
	)
	if err != nil {
		t.Fatalf("WriteResponsesResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	usage := payload["usage"].(map[string]any)
	if usage["input_tokens"] != float64(6034) {
		t.Fatalf("input_tokens = %v, want 6034 (folded)", usage["input_tokens"])
	}
	if usage["total_tokens"] != float64(6044) {
		t.Fatalf("total_tokens = %v, want 6044", usage["total_tokens"])
	}
	details := usage["input_tokens_details"].(map[string]any)
	if details["cached_tokens"] != float64(6034) {
		t.Fatalf("cached_tokens = %v, want 6034", details["cached_tokens"])
	}
}

// fullyCachedAnthropicStream is the edge case where the ENTIRE prompt was served
// from cache: message_start reports input_tokens:0 with cache_read_input_tokens.
const fullyCachedAnthropicStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_03","type":"message","role":"assistant","content":[],"model":"claude-haiku-4-5","stop_reason":null,"usage":{"input_tokens":0,"cache_read_input_tokens":6034,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}
`

// cacheOnDeltaAnthropicStream is the defensive shape where message_start carries
// an all-zero usage object and cache_read_input_tokens first appears on a later
// message_delta. message_start is Anthropic-exclusive, so the convention must
// still be recorded despite the zero counters up front.
const cacheOnDeltaAnthropicStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_04","type":"message","role":"assistant","content":[],"model":"claude-haiku-4-5","stop_reason":null,"usage":{"input_tokens":0,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"y"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4,"cache_read_input_tokens":6034}}

event: message_stop
data: {"type":"message_stop"}
`

// TestUsageChunkFoldsCacheArrivingOnDelta guards the all-zero-message_start plus
// cache-on-message_delta shape: InputExcludesCache must be recorded from the
// message_start (Anthropic-exclusive) so the late cache tokens still fold into
// prompt_tokens (6034) instead of leaving prompt_tokens:0 with cached_tokens:6034.
func TestUsageChunkFoldsCacheArrivingOnDelta(t *testing.T) {
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(cacheOnDeltaAnthropicStream), &out, "id1", "claude-haiku-4-5", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage == nil || !result.Usage.InputExcludesCache {
		t.Fatalf("expected InputExcludesCache=true from all-zero message_start: %#v", result.Usage)
	}
	blocks := strings.Split(strings.TrimSpace(out.String()), "\n\n")
	var chunk map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(blocks[len(blocks)-2], "data: ")), &chunk); err != nil {
		t.Fatalf("unmarshal usage chunk: %v", err)
	}
	usage := chunk["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(6034) {
		t.Fatalf("prompt_tokens = %v, want 6034", usage["prompt_tokens"])
	}
	details := usage["prompt_tokens_details"].(map[string]any)
	if details["cached_tokens"] != float64(6034) {
		t.Fatalf("cached_tokens = %v, want 6034", details["cached_tokens"])
	}
}

// TestUsageChunkFoldsFullyCachedAnthropicPrompt guards the input_tokens:0 edge
// case: message_start is Anthropic-exclusive even with a zero uncached
// remainder, so the cache tokens must still fold into prompt_tokens (6034) and
// not leave prompt_tokens:0 with cached_tokens:6034.
func TestUsageChunkFoldsFullyCachedAnthropicPrompt(t *testing.T) {
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(fullyCachedAnthropicStream), &out, "id1", "claude-haiku-4-5", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage == nil || !result.Usage.InputExcludesCache {
		t.Fatalf("expected InputExcludesCache=true for fully-cached message_start: %#v", result.Usage)
	}

	blocks := strings.Split(strings.TrimSpace(out.String()), "\n\n")
	var chunk map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(blocks[len(blocks)-2], "data: ")), &chunk); err != nil {
		t.Fatalf("unmarshal usage chunk: %v", err)
	}
	usage := chunk["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(6034) {
		t.Fatalf("prompt_tokens = %v, want 6034 (fully-cached fold)", usage["prompt_tokens"])
	}
	details := usage["prompt_tokens_details"].(map[string]any)
	if details["cached_tokens"] != float64(6034) {
		t.Fatalf("cached_tokens = %v, want 6034", details["cached_tokens"])
	}
}
