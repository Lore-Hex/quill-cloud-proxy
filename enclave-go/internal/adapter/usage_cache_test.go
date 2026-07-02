package adapter

import "testing"

// TestChatCompletionUsageAnthropicFoldsCacheReadIntoPromptTokens covers the
// Anthropic convention (inputExcludesCache=true): Anthropic reports input_tokens
// exclusive of cache, so a cache HIT with input_tokens=3, cache_read=6034 must
// surface as prompt_tokens=6037 with prompt_tokens_details.cached_tokens=6034 —
// keeping cached_tokens a subset of prompt_tokens (a client computing
// uncached = prompt_tokens - cached_tokens must not go negative).
func TestChatCompletionUsageAnthropicFoldsCacheReadIntoPromptTokens(t *testing.T) {
	usage := chatCompletionUsage(3, 10, 6034, 0, 0, true)

	if got := usage["prompt_tokens"].(int); got != 6037 {
		t.Fatalf("prompt_tokens = %d, want 6037", got)
	}
	if got := usage["total_tokens"].(int); got != 6047 {
		t.Fatalf("total_tokens = %d, want 6047", got)
	}
	details, ok := usage["prompt_tokens_details"].(map[string]any)
	if !ok {
		t.Fatalf("prompt_tokens_details missing: %#v", usage)
	}
	cached := details["cached_tokens"].(int)
	if cached != 6034 {
		t.Fatalf("cached_tokens = %d, want 6034", cached)
	}
	if cached > usage["prompt_tokens"].(int) {
		t.Fatalf("cached_tokens %d exceeds prompt_tokens %d", cached, usage["prompt_tokens"].(int))
	}
}

// TestChatCompletionUsageAnthropicCacheWriteTurn covers the cache-CREATION turn:
// cache_creation tokens are part of the prompt (prompt_tokens includes them)
// but nothing was READ from cache, so cached_tokens is absent.
func TestChatCompletionUsageAnthropicCacheWriteTurn(t *testing.T) {
	usage := chatCompletionUsage(3, 10, 0, 6034, 0, true)

	if got := usage["prompt_tokens"].(int); got != 6037 {
		t.Fatalf("prompt_tokens = %d, want 6037", got)
	}
	if got := usage["total_tokens"].(int); got != 6047 {
		t.Fatalf("total_tokens = %d, want 6047", got)
	}
	if _, ok := usage["prompt_tokens_details"]; ok {
		t.Fatalf("prompt_tokens_details must be absent on a pure cache-write turn: %#v", usage)
	}
}

// TestChatCompletionUsageOpenAICompatDoesNotDoubleCount guards the regression
// flagged in review: OpenAI-compatible and Gemini upstreams report a
// cache-INCLUSIVE prompt count (inputExcludesCache=false), so cached tokens must
// NOT be folded in again. Upstream prompt_tokens=1000 with cached=900 stays
// prompt_tokens=1000, not 1900.
func TestChatCompletionUsageOpenAICompatDoesNotDoubleCount(t *testing.T) {
	usage := chatCompletionUsage(1000, 20, 900, 0, 0, false)

	if got := usage["prompt_tokens"].(int); got != 1000 {
		t.Fatalf("prompt_tokens = %d, want 1000 (no double-count)", got)
	}
	if got := usage["total_tokens"].(int); got != 1020 {
		t.Fatalf("total_tokens = %d, want 1020", got)
	}
	details, ok := usage["prompt_tokens_details"].(map[string]any)
	if !ok {
		t.Fatalf("prompt_tokens_details missing: %#v", usage)
	}
	if cached := details["cached_tokens"].(int); cached != 900 || cached > usage["prompt_tokens"].(int) {
		t.Fatalf("cached_tokens = %d, want 900 and <= prompt_tokens", cached)
	}
}

// TestChatCompletionUsageClampsCachedToPromptFloor guards the degenerate case
// where inputTokens is a chars/4 estimate that undershoots the reported cache
// (e.g. an upstream usage with prompt_tokens missing/0 but cache_read>0, for
// which realOrEstimatedTokens substitutes an estimate). prompt_tokens must still
// be >= cached_tokens so a client computing uncached = prompt - cached never
// goes negative.
func TestChatCompletionUsageClampsCachedToPromptFloor(t *testing.T) {
	// Estimated input 512, cached 900, non-Anthropic (no fold): prompt must be
	// clamped up to 900, not left at 512.
	usage := chatCompletionUsage(512, 6, 900, 0, 0, false)
	prompt := usage["prompt_tokens"].(int)
	cached := usage["prompt_tokens_details"].(map[string]any)["cached_tokens"].(int)
	if prompt != 900 {
		t.Fatalf("prompt_tokens = %d, want 900 (clamped to cache floor)", prompt)
	}
	if cached > prompt {
		t.Fatalf("cached_tokens %d exceeds prompt_tokens %d", cached, prompt)
	}
	if usage["total_tokens"].(int) != 906 {
		t.Fatalf("total_tokens = %d, want 906", usage["total_tokens"].(int))
	}
}

// TestChatCompletionUsageNoCacheUnchanged locks in that the non-cached shape is
// untouched under either convention: no cache tokens => prompt_tokens is exactly
// the input count and no prompt_tokens_details is emitted.
func TestChatCompletionUsageNoCacheUnchanged(t *testing.T) {
	for _, excludes := range []bool{true, false} {
		usage := chatCompletionUsage(100, 20, 0, 0, 0, excludes)
		if got := usage["prompt_tokens"].(int); got != 100 {
			t.Fatalf("inputExcludesCache=%v: prompt_tokens = %d, want 100", excludes, got)
		}
		if got := usage["total_tokens"].(int); got != 120 {
			t.Fatalf("inputExcludesCache=%v: total_tokens = %d, want 120", excludes, got)
		}
		if _, ok := usage["prompt_tokens_details"]; ok {
			t.Fatalf("inputExcludesCache=%v: prompt_tokens_details must be absent with no cache: %#v", excludes, usage)
		}
	}
}
