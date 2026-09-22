package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Callers pass the decoded HTTP body, so these assertions cover serialization
// and the response writer as well as the metadata helper.
func assertDecideRouting(t *testing.T, payload map[string]any, wantJSON string) {
	t.Helper()
	var want map[string]any
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatal(err)
	}
	metadata, _ := payload["trustedrouter"].(map[string]any)
	routing, ok := metadata["routing"].(map[string]any)
	if !ok || !reflect.DeepEqual(routing, want) {
		t.Fatalf("routing = %v, want %v", routing, want)
	}
}

func TestDecideRoutingPreservesTheResponseContract(t *testing.T) {
	for _, tc := range []struct {
		name          string
		settlement    *trustedrouter.SettleResult
		authorization *trustedrouter.Authorization
		served        llm.InvokeOptions
		want          string
	}{
		{
			name:       "served upstream without settlement provider",
			served:     llm.InvokeOptions{Provider: "siliconflow", EndpointID: "google/gemma-4-12b-it@siliconflow/prepaid"},
			settlement: &trustedrouter.SettleResult{CostMicrodollars: 123},
			want:       `{"selected_model":"google/gemma-4-12b-it","selected_provider":"siliconflow","selected_endpoint":"google/gemma-4-12b-it@siliconflow/prepaid"}`,
		},
		{
			name:       "settlement identifies the served provider",
			served:     llm.InvokeOptions{Provider: "preferred"},
			settlement: &trustedrouter.SettleResult{Model: "settled-model", Provider: "siliconflow", Region: "us-central1", CostMicrodollars: 123},
			want:       `{"selected_model":"settled-model","selected_provider":"siliconflow"}`,
		},
		{
			name:       "gateway service identified by settlement",
			settlement: &trustedrouter.SettleResult{Provider: "trustedrouter"},
			want:       `{"selected_model":"google/gemma-4-12b-it","selected_provider":"trustedrouter"}`,
		},
		{
			name:          "unrecorded upstream is not the gateway",
			authorization: &trustedrouter.Authorization{Provider: "preferred", EndpointID: "preferred-endpoint"},
			want:          `{"selected_model":"google/gemma-4-12b-it"}`,
		},
		{
			name: "no route information",
			want: `{"selected_model":"google/gemma-4-12b-it"}`,
		},
		{
			name:          "hidden route",
			authorization: &trustedrouter.Authorization{HidePublicMetadata: true, ResponseModel: decide.TrevModelID},
			served:        llm.InvokeOptions{Provider: "siliconflow", EndpointID: "private-endpoint"},
			settlement:    &trustedrouter.SettleResult{Model: "private-model", Provider: "private-provider", Region: "private-region", CostMicrodollars: 123},
			want:          `{"selected_model":"trustedrouter/trev-1.0","selected_provider":"trustedrouter"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writeDecideResponse(context.Background(), &out, decideResponse{
				Model:   "google/gemma-4-12b-it",
				Answers: map[string]decide.Answer{"refund": {Type: "noul", Probability: pf(0.97)}},
				Usage:   decideUsage{InputTokens: 300, OutputTokens: 20},
			}, tc.settlement, tc.authorization, decideRoutingMetadata{Served: tc.served})
			head, body, ok := strings.Cut(out.String(), "\r\n\r\n")
			if !ok || !strings.HasPrefix(head, "HTTP/1.1 200") {
				t.Fatalf("response = %s", out.String())
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(body), &payload); err != nil {
				t.Fatal(err)
			}
			assertDecideRouting(t, payload, tc.want)
			// Compare original bytes, including token spelling and answer order;
			// decoding into the old struct would silently ignore added usage costs.
			original, _, added := strings.Cut(body, `,"trustedrouter":`)
			const wantOriginal = `{"model":"google/gemma-4-12b-it","answers":{"refund":{"type":"noul","probability":0.97}},"usage":{"inputTokens":300,"outputTokens":20}}`
			if !added || original+"}" != wantOriginal {
				t.Fatalf("pre-existing response fields changed: %s", body)
			}
		})
	}
}

func TestBatchDecideRoutingAgreesWithProviderUsage(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		var out bytes.Buffer
		ctx := context.WithValue(context.Background(), batchExecutionContextKey{}, true)
		writeDecideResponse(ctx, &out, decideResponse{Model: decide.TrevModelID},
			&trustedrouter.SettleResult{Model: "private-model", Provider: "siliconflow", Region: "us-central1", CostMicrodollars: 123},
			&trustedrouter.Authorization{HidePublicMetadata: hidden, ResponseModel: decide.TrevModelID},
			decideRoutingMetadata{Served: llm.InvokeOptions{EndpointID: "private-endpoint"}})
		_, body, _ := strings.Cut(out.String(), "\r\n\r\n")
		var payload map[string]any
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatal(err)
		}
		routing := payload["trustedrouter"].(map[string]any)["routing"].(map[string]any)
		usage := payload["usage"].(map[string]any)
		providerUsage := usage["provider_usage"].(map[string]any)
		for _, key := range []string{"selected_model", "selected_provider"} {
			if routing[key] != providerUsage[key] {
				t.Errorf("hidden=%v: %s disagrees: %s", hidden, key, body)
			}
		}
		if usage["cost_microdollars"] != float64(123) {
			t.Errorf("existing batch accounting changed: %s", body)
		}
		if hidden && (routing["selected_endpoint"] != nil || providerUsage["region"] != nil) {
			t.Errorf("hidden route leaked: %s", body)
		}
	}
}
