package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

// TestRealOrEstimatedTokensFullCacheHitKeepsRealZeroInput guards the
// non-streaming full prompt-cache hit: Anthropic reports input_tokens:0 with
// cache_read_input_tokens>0, and that zero is REAL (the whole prompt was
// served from cache). realOrEstimatedTokens must not substitute the chars/4
// estimate here — doing so both settles billing on an inflated uncached count
// and double-counts prompt_tokens once the OpenAI usage folds cache tokens onto
// an Anthropic uncached input.
func TestRealOrEstimatedTokensFullCacheHitKeepsRealZeroInput(t *testing.T) {
	result := adapter.StreamResult{Usage: &adapter.StreamUsage{
		InputTokens:          0,
		OutputTokens:         5,
		CacheReadInputTokens: 6034,
		InputExcludesCache:   true,
	}}
	in, out, estimated := realOrEstimatedTokens(result, 9999 /* deliberately-wrong estimate */, 5)
	if in != 0 {
		t.Fatalf("input = %d, want 0 (real uncached count, not the estimate)", in)
	}
	if out != 5 {
		t.Fatalf("output = %d, want 5", out)
	}
	if estimated {
		t.Fatalf("usageEstimated = true, want false (usage was real)")
	}
}

// TestFusionUsageTotalsFoldPerChild verifies aggregated orchestration usage
// folds cache PER CHILD by provider convention, so a mixed panel stays coherent:
// an Anthropic full cache hit (input 0, cache_read 6034, InputExcludesCache)
// folds to 6034, while an OpenAI-compatible child whose input already includes
// its cached subset (input 1000, cache_read 900) passes through unfolded. A
// blanket fold on the summed total would over-count the OpenAI child's cache.
func TestFusionUsageTotalsFoldPerChild(t *testing.T) {
	anthropicHit := fusionCallResult{
		InputTokens:  0,
		OutputTokens: 5,
		Result: adapter.StreamResult{Usage: &adapter.StreamUsage{
			InputTokens: 0, OutputTokens: 5, CacheReadInputTokens: 6034, InputExcludesCache: true,
		}},
	}
	openAIHit := fusionCallResult{
		InputTokens:  1000,
		OutputTokens: 8,
		Result: adapter.StreamResult{Usage: &adapter.StreamUsage{
			InputTokens: 1000, OutputTokens: 8, CacheReadInputTokens: 900, // InputExcludesCache: false
		}},
	}
	in, out := fusionPanelUsageTotals([]fusionCallResult{anthropicHit, openAIHit})
	if in != 7034 {
		t.Fatalf("input = %d, want 7034 (6034 Anthropic fold + 1000 OpenAI passthrough)", in)
	}
	if out != 13 {
		t.Fatalf("output = %d, want 13", out)
	}
}

// TestRealOrEstimatedTokensMissingInputNoCacheStillEstimates locks in the
// unchanged fallback: when input is missing AND no cache tokens were reported,
// the chars/4 estimate is still used and the settlement is flagged estimated.
func TestRealOrEstimatedTokensMissingInputNoCacheStillEstimates(t *testing.T) {
	result := adapter.StreamResult{Usage: &adapter.StreamUsage{InputTokens: 0, OutputTokens: 7}}
	in, out, estimated := realOrEstimatedTokens(result, 42, 7)
	if in != 42 || out != 7 || !estimated {
		t.Fatalf("got (%d, %d, %v), want (42, 7, true)", in, out, estimated)
	}
}

// TestRealOrEstimatedTokensAnthropicZeroInputNoCacheEstimates guards the other
// half of the gate: an Anthropic stream (InputExcludesCache) whose input_tokens
// is 0 but reports NO cache tokens leaves the prompt unaccounted, so the zero is
// missing and must fall back to the estimate rather than settling at input 0.
func TestRealOrEstimatedTokensAnthropicZeroInputNoCacheEstimates(t *testing.T) {
	result := adapter.StreamResult{Usage: &adapter.StreamUsage{
		InputTokens: 0, OutputTokens: 4, InputExcludesCache: true, // no cache tokens
	}}
	in, out, estimated := realOrEstimatedTokens(result, 256, 4)
	if in != 256 || out != 4 || !estimated {
		t.Fatalf("got (%d, %d, %v), want (256, 4, true)", in, out, estimated)
	}
}

// TestRealOrEstimatedTokensNonAnthropicZeroInputWithCacheEstimates guards the
// non-Anthropic side: OpenAI-compatible/Gemini report a cache-INCLUSIVE prompt
// count on message_delta (InputExcludesCache stays false), so a zero prompt
// count there is MISSING — the estimate bypass must NOT trigger just because
// cache tokens are present, or settlement would send input 0 and public usage
// would show prompt_tokens:0 with cached_tokens>0.
func TestRealOrEstimatedTokensNonAnthropicZeroInputWithCacheEstimates(t *testing.T) {
	result := adapter.StreamResult{Usage: &adapter.StreamUsage{
		InputTokens: 0, OutputTokens: 6, CacheReadInputTokens: 900, InputExcludesCache: false,
	}}
	in, out, estimated := realOrEstimatedTokens(result, 512, 6)
	if in != 512 || out != 6 || !estimated {
		t.Fatalf("got (%d, %d, %v), want (512, 6, true)", in, out, estimated)
	}
}
