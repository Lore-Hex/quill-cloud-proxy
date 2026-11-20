package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// claude-haiku-5.5 as the catalog priced it on 2026-11-19: Anthropic direct
// 105,500/527,500 and Bedrock 116,050/580,250 microdollars a million
// prompt/output tokens. The authorization's cap is the priciest candidate's
// price of the prompt estimate plus the default 512-token output budget.
var (
	haikuDirect  = trustedrouter.PriceRates{InputMicroPerMillion: 105_500, OutputMicroPerMillion: 527_500, CachedInputMicroPerMillion: 10_550, CacheCreationMicroPerMillion: 131_875}
	haikuBedrock = trustedrouter.PriceRates{InputMicroPerMillion: 116_050, OutputMicroPerMillion: 580_250, CachedInputMicroPerMillion: 11_605, CacheCreationMicroPerMillion: 145_062}
)

func haikuCap(promptEstimate int) int64 {
	return max(
		stageDUsageMicro(trustedrouter.CandidatePrice{}, haikuDirect, promptEstimate, 512, 0, 0),
		stageDUsageMicro(trustedrouter.CandidatePrice{}, haikuBedrock, promptEstimate, 512, 0, 0),
	)
}

func haikuController(rates trustedrouter.PriceRates, promptEstimate int) *stageDController {
	return &stageDController{
		auth:   &trustedrouter.Authorization{AuthorizationID: "auth"},
		config: stageDConfig{terminateAtCap: true},
		meter:  stageDMeter{promptTokens: promptEstimate}, authorizedPromptTokens: promptEstimate,
		capMicro: haikuCap(promptEstimate), hasPrice: true,
		price:        trustedrouter.CandidatePrice{Rates: rates, Rounding: "half_up_per_million"},
		lastAccepted: time.Now(),
	}
}

// The report's matrix, as the enclave meters it: the prompt estimate is
// EstimateInputTokens of the messages, and message_start then reports the
// provider's prompt (tool JSON, Anthropic's tool-use system prompt, a finer
// tokenizer). On Anthropic direct the cap was passed before the first output
// token once delivered > about 1.1 x estimate + 2,816: the stream ended at
// once, empty, finish_reason "length", tr_finish_reason "cap_reached".
func TestStageDCapAllowsAPromptAboveItsEstimate(t *testing.T) {
	cases := []struct {
		name            string
		promptEstimate  int
		deliveredPrompt int
		wasCut          bool
	}{
		{"one tool, 6,000-char description", 10, 1_900, false},
		{"one tool, 9,000-char description", 10, 2_900, true},
		{"13 tools, 27 KB of tool JSON", 10, 9_500, true},
		{"no tools, 24,000-char message", 6_004, 8_400, false},
		{"no tools, 40,000-char message", 10_004, 14_000, true},
	}
	for _, tc := range cases {
		for _, endpoint := range []struct {
			name  string
			rates trustedrouter.PriceRates
		}{{"direct", haikuDirect}, {"bedrock", haikuBedrock}} {
			t.Run(tc.name+"/"+endpoint.name, func(t *testing.T) {
				controller := haikuController(endpoint.rates, tc.promptEstimate)
				controller.observeUsage(&adapter.StreamUsage{InputTokens: tc.deliveredPrompt})
				first := adapter.StreamDelta{Type: "text_delta", Text: "Hello"}
				if endpoint.name == "direct" {
					running := stageDUsageMicro(controller.price, endpoint.rates, tc.deliveredPrompt, 1, 0, 0)
					if (running > controller.capMicro) != tc.wasCut {
						t.Fatalf("running=%d cap=%d: the threshold moved", running, controller.capMicro)
					}
				}
				if err := controller.beforeSlice(first); err != nil {
					t.Fatalf("first slice cut: %v", err)
				}
				if err := controller.afterSlice(first); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// The allowance is the prompt's excess, never more output: a stream whose
// prompt overran its estimate is still cut once its output passes the
// budget the cap priced.
func TestStageDCapStillBoundsTheOutputAfterAPromptOverrun(t *testing.T) {
	controller := haikuController(haikuBedrock, 10)
	// No gateway here: keep the 256-token heartbeat cadence from firing.
	controller.lastOutput = 1 << 30
	controller.observeUsage(&adapter.StreamUsage{InputTokens: 9_500})
	budget := adapter.StreamDelta{Type: "text_delta", Text: strings.Repeat("x", 4*adapter.MaxMeterChunkTokens)}
	for controller.meter.outputTokens()+adapter.MaxMeterChunkTokens <= 512 {
		if err := controller.beforeSlice(budget); err != nil {
			t.Fatalf("cut within the budget at %d tokens: %v", controller.meter.outputTokens(), err)
		}
		if err := controller.afterSlice(budget); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 1_000; i++ {
		err := controller.beforeSlice(budget)
		if termination, ok := err.(*adapter.ControlledTermination); ok {
			if termination.TRFinishReason != "cap_reached" || controller.meter.outputTokens() > 512 {
				t.Fatalf("termination=%#v at %d output tokens", termination, controller.meter.outputTokens())
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := controller.afterSlice(budget); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("never cut; %d output tokens", controller.meter.outputTokens())
}

// A cache write above the estimate is prompt too: it bills 1.25 times the
// input rate and is part of the excess.
func TestStageDCapAllowsACacheWriteAboveTheEstimate(t *testing.T) {
	controller := haikuController(haikuDirect, 10)
	controller.observeUsage(&adapter.StreamUsage{InputTokens: 10, CacheCreationInputTokens: 6_000, InputExcludesCache: true})
	if err := controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: "Hello"}); err != nil {
		t.Fatalf("first slice cut: %v", err)
	}
}
