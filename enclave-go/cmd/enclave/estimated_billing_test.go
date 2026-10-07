package main

import (
	"math"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestEstimatedBufferRequiresReviewedSuccessfulPrepaidRoute(t *testing.T) {
	for _, scenario := range []string{"eligible", "reported", "partial", "reported-zero", "cache", "reasoning", "failed", "incomplete", "empty", "byok", "other-provider", "unknown-model", "wrong-endpoint", "no-cap", "no-snapshot", "invalid-snapshot", "no-authority", "receipt", "custom-model", "fallback-byok", "fallback-prepaid"} {
		t.Run(scenario, func(t *testing.T) {
			auth := abliterateTestAuthorization()
			req := &types.OpenAIChatRequest{MaxTokens: intPointer(32)}
			result := adapter.StreamResult{Text: "Hello world", FinishReason: "stop"}
			model, endpoint := abliterateTestModel, "served"
			wantInput, wantOutput := 5, 2
			switch scenario {
			case "eligible":
				wantInput, wantOutput = 10, 4
			case "reported":
				result.Usage = &adapter.StreamUsage{InputTokens: 5, OutputTokens: 2}
			case "partial":
				result.Usage = &adapter.StreamUsage{InputTokens: 5}
			case "reported-zero":
				result.Usage = &adapter.StreamUsage{}
				wantInput, wantOutput = 10, 4
			case "cache":
				result.Usage = &adapter.StreamUsage{CacheReadInputTokens: 5}
			case "reasoning":
				result.Usage = &adapter.StreamUsage{ReasoningTokens: 1}
			case "failed":
				result.FinishReason = "error"
			case "incomplete":
				result.FinishReason = ""
			case "empty":
				result.Text = " \n"
			case "byok":
				auth.UsageType = "BYOK"
			case "other-provider":
				auth.Provider = "other"
			case "unknown-model":
				model = "abliterate/new-model"
				auth.Model = model
			case "wrong-endpoint":
				endpoint = "not-authorized"
			case "no-cap":
				auth.CapMicro, auth.EstimatedCostMicrodollars = 0, 0
			case "no-snapshot":
				auth.CandidatePrices = nil
			case "invalid-snapshot":
				auth.CandidatePrices[0].Rates.InputMicroPerMillion = -1
			case "no-authority":
				auth.CandidateCostReporting = false
			case "receipt":
				auth.ReceiptFeeBasisPoints = 1200
			case "custom-model":
				auth.CustomModel = &trustedrouter.CustomModel{}
			case "fallback-byok":
				auth.RouteCandidates = []trustedrouter.RouteCandidate{{EndpointID: endpoint, Model: model, Provider: "abliterate", UsageType: "BYOK"}}
			case "fallback-prepaid":
				auth.Model, auth.Provider, auth.EndpointID, auth.UsageType = "other-model", "other", "first", "BYOK"
				auth.RouteCandidates = []trustedrouter.RouteCandidate{{EndpointID: endpoint, Model: model, Provider: "abliterate", UsageType: "Credits"}}
				wantInput, wantOutput = 10, 4
			}
			in, out := bufferedMissingUsage(result, 5, 2, model, req, auth, endpoint)
			if in != wantInput || out != wantOutput {
				t.Fatalf("got %d/%d want %d/%d", in, out, wantInput, wantOutput)
			}
		})
	}
}

func TestEstimatedBufferPreservesExactUsage(t *testing.T) {
	result := adapter.StreamResult{Text: "Hello world", FinishReason: "stop", Usage: &adapter.StreamUsage{InputTokens: 17, OutputTokens: 9}}
	in, out, estimated := tokensForSettlement(result, 5, 2, abliterateTestModel, &types.OpenAIChatRequest{}, abliterateTestAuthorization(), "served")
	if in != 17 || out != 9 || estimated {
		t.Fatalf("changed provider usage: %d/%d estimated=%v", in, out, estimated)
	}
}

func TestEstimatedBufferNeverExceedsAuthorizedCostOrOutputLimit(t *testing.T) {
	result := adapter.StreamResult{Text: "Hello world", FinishReason: "stop"}
	for input := 1; input < 20; input++ {
		for output := 1; output < 20; output++ {
			for cap := 1; cap < 100; cap++ {
				auth := abliterateTestAuthorization()
				auth.CapMicro, auth.EstimatedCostMicrodollars = int64(cap), cap+5
				maxOutput := output + 1
				in, out := bufferedMissingUsage(result, input, output, abliterateTestModel, &types.OpenAIChatRequest{MaxTokens: &maxOutput}, auth, "served")
				before, _ := auth.CandidatePrices[0].CostMicrodollars(input, output, 0, 0, input)
				after, valid := auth.CandidatePrices[0].CostMicrodollars(in, out, 0, 0, in)
				if !valid || in < input || out < output || in > input*2 || out > output*2 || out > maxOutput || (before <= cap && after > cap) || (before > cap && (in != input || out != output)) {
					t.Fatalf("input=%d output=%d cap=%d -> %d/%d cost=%d", input, output, cap, in, out, after)
				}
			}
		}
	}
}

func TestEstimatedBufferOverflowAndDefaultCompletionLimit(t *testing.T) {
	result := adapter.StreamResult{Text: "Hello", FinishReason: "length"}
	auth := abliterateTestAuthorization()
	auth.CapMicro, auth.EstimatedCostMicrodollars = 100000, 100000
	for _, count := range []int{-1, 0, math.MaxInt, math.MaxInt / 2} {
		in, out := bufferedMissingUsage(result, count, count, abliterateTestModel, &types.OpenAIChatRequest{}, auth, "served")
		if in != count || out != count {
			t.Fatalf("unsafe count changed: %d -> %d/%d", count, in, out)
		}
	}
	_, out := bufferedMissingUsage(result, 5, 400, abliterateTestModel, &types.OpenAIChatRequest{}, auth, "served")
	if out != 512 {
		t.Fatalf("default output bound = %d", out)
	}
	auth.EstimatedCostMicrodollars = 18
	in, out := bufferedMissingUsage(result, 5, 2, abliterateTestModel, &types.OpenAIChatRequest{}, auth, "served")
	if in != 5 || out != 2 {
		t.Fatalf("ignored lower reservation: %d/%d", in, out)
	}
}

func TestStageDMissingUsageBufferOnlyOnHealthyCompletion(t *testing.T) {
	for _, reason := range []string{"", "cap", "heartbeat_lost", "client_disconnected"} {
		auth := abliterateTestAuthorization()
		c := &stageDController{auth: auth, endpointID: "served", started: time.Now(), meter: stageDMeter{promptTokens: 5, semanticBytes: 8}}
		terminal := adapter.StreamTerminal{Result: adapter.StreamResult{Text: "abcdefgh", FinishReason: "stop"}, FinishReason: "stop", TRFinishReason: reason}
		usage := c.terminalUsage(terminal, "req", "responses", abliterateTestModel, &types.OpenAIChatRequest{}, 0)
		wantInput, wantOutput := 5, 2
		if reason == "" {
			wantInput, wantOutput = 10, 4
		}
		if usage.InputTokens != wantInput || usage.OutputTokens != wantOutput || !usage.UsageEstimated {
			t.Fatalf("reason=%q usage=%+v", reason, usage)
		}
	}
}
