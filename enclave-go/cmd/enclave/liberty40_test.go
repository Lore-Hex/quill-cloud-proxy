package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestLiberty40IsAUSOnlyFusionWithMuseSparkFusing(t *testing.T) {
	if _, ok := advisorPresetForModel(trustedRouterLiberty40Model); ok {
		t.Fatal("Liberty 4.0 must be a fusion, not an advisor combo")
	}
	if !isFusionModel(trustedRouterLiberty40Model) {
		t.Fatal("Liberty 4.0 must be a fusion model")
	}
	preset, panel, ok := fusionPresetPanelForModel(trustedRouterLiberty40Model)
	wantPanel := []string{"nvidia/nemotron-3.5-super-vl", "reflection/beam-1.0", "thinkingmachines/inkling"}
	if !ok || preset != "liberty-4.0" || !reflect.DeepEqual(panel, wantPanel) {
		t.Fatalf("panel = %q %#v, want liberty-4.0 %#v", preset, panel, wantPanel)
	}
	wantFusers := []string{"meta-models/muse-spark-open", "reflection/beam-1.0", "thinkingmachines/inkling", "nvidia/nemotron-3.5-super-vl"}
	judges, err := fusionJudgeModels(fusionConfig{}, trustedRouterLiberty40Model)
	if err != nil || !reflect.DeepEqual(judges, wantFusers) {
		t.Fatalf("judge models = %#v (%v), want %#v", judges, err, wantFusers)
	}
	finals, err := fusionFinalModels(fusionConfig{}, trustedRouterLiberty40Model, panel[0])
	if err != nil || !reflect.DeepEqual(finals, wantFusers) {
		t.Fatalf("final models = %#v (%v), want %#v", finals, err, wantFusers)
	}

	config, requested, err := fusionConfigForRequest(&types.OpenAIChatRequest{Model: trustedRouterLiberty40Model})
	if err != nil || !requested {
		t.Fatalf("fusionConfigForRequest: requested=%v err=%v", requested, err)
	}
	if config.ProviderJurisdiction != providerJurisdictionUS {
		t.Fatalf("provider jurisdiction = %q, want US", config.ProviderJurisdiction)
	}
	if !config.FuserFailover {
		t.Fatal("Liberty 4.0 fusers must fail over on provider errors")
	}

	if !isLongContextCombo(trustedRouterLiberty40Model) {
		t.Fatal("Liberty 4.0 members must be pinned to their matched-window routes")
	}
	for _, member := range append(append([]string(nil), panel...), wantFusers...) {
		providers := longContextComboProviders[member]
		if len(providers) == 0 {
			t.Fatalf("no reviewed matched-window route for %s", member)
		}
	}
}

func TestOnlyLiberty40EnablesFuserFailover(t *testing.T) {
	for _, model := range []string{trustedRouterPrometheus40Model, trustedRouterLiberty10Model, trustedRouterOpenPatcherS1Model} {
		config, _, err := fusionConfigForRequest(&types.OpenAIChatRequest{Model: model})
		if err != nil {
			t.Fatalf("%s: %v", model, err)
		}
		if config.FuserFailover {
			t.Fatalf("%s must keep stop-on-provider-error fuser semantics", model)
		}
	}
}

func TestFusionCanTryNextFuser(t *testing.T) {
	providerErr := errors.New("llm/upstream: http 502: provider error")
	balanceErr := &trustedrouter.ControlPlaneError{StatusCode: http.StatusPaymentRequired, Type: "insufficient_credits"}
	unroutable := &fusionModelFallbackError{err: errors.New("model_not_supported")}
	on := fusionConfig{FuserFailover: true}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		config fusionConfig
		err    error
		want   bool
	}{
		{"unroutable model always falls through", context.Background(), fusionConfig{}, unroutable, true},
		{"provider error stops without failover", context.Background(), fusionConfig{}, providerErr, false},
		{"provider error falls through with failover", context.Background(), on, providerErr, true},
		{"control-plane refusal stops even with failover", context.Background(), on, balanceErr, false},
		{"canceled request stops even with failover", canceled, on, providerErr, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fusionCanTryNextFuser(tt.ctx, tt.config, tt.err); got != tt.want {
				t.Fatalf("fusionCanTryNextFuser = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLiberty40FusesWhatReturnedAndFailsOverFusersThroughLocalGateway(t *testing.T) {
	tests := []struct {
		name       string
		stream     bool
		failModels map[string]bool
		wantFinal  string
		wantCalls  map[string]int
	}{
		{
			name:       "Muse Spark down: Beam fuses",
			failModels: map[string]bool{"meta-models/muse-spark-open": true},
			wantFinal:  "reflection/beam-1.0",
			// Beam answers on the panel, then takes over as judge and final.
			wantCalls: map[string]int{"meta-models/muse-spark-open": 2, "reflection/beam-1.0": 3, "thinkingmachines/inkling": 1, "nvidia/nemotron-3.5-super-vl": 1},
		},
		{
			name:       "Muse Spark down while streaming: Beam fuses",
			stream:     true,
			failModels: map[string]bool{"meta-models/muse-spark-open": true},
			wantFinal:  "reflection/beam-1.0",
			wantCalls:  map[string]int{"meta-models/muse-spark-open": 2, "reflection/beam-1.0": 3, "thinkingmachines/inkling": 1, "nvidia/nemotron-3.5-super-vl": 1},
		},
		{
			name: "Muse Spark, Beam and Nemotron down: Inkling's lone panel answer is fused by Inkling",
			failModels: map[string]bool{
				"meta-models/muse-spark-open":  true,
				"reflection/beam-1.0":          true,
				"nvidia/nemotron-3.5-super-vl": true,
			},
			wantFinal: "thinkingmachines/inkling",
			wantCalls: map[string]int{"meta-models/muse-spark-open": 2, "reflection/beam-1.0": 3, "thinkingmachines/inkling": 3, "nvidia/nemotron-3.5-super-vl": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trGateway, recorder, closeGateway := newFusionGatewayRecorder(t)
			defer closeGateway()
			streamer := &fusionEchoLLM{failModels: tt.failModels}
			serverConn, client := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)
			}()

			requestBody, err := json.Marshal(map[string]any{
				"model":      trustedRouterLiberty40Model,
				"stream":     tt.stream,
				"messages":   []map[string]any{{"role": "user", "content": "Reply with a short local test answer."}},
				"max_tokens": 512,
			})
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			if _, err := fmt.Fprintf(
				client,
				"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer local-liberty-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				len(requestBody),
				requestBody,
			); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			<-done
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
			if !strings.Contains(string(body), "final answer from "+tt.wantFinal) {
				t.Fatalf("final answer was not written by %s: %s", tt.wantFinal, body)
			}

			streamer.mu.Lock()
			gotCalls := map[string]int{}
			for _, call := range streamer.calls {
				gotCalls[call.Model]++
			}
			streamer.mu.Unlock()
			if !reflect.DeepEqual(gotCalls, tt.wantCalls) {
				t.Fatalf("calls per model = %#v, want %#v", gotCalls, tt.wantCalls)
			}

			recorder.mu.Lock()
			authorize := append([]map[string]any(nil), recorder.authorize...)
			recorder.mu.Unlock()
			if len(authorize) == 0 {
				t.Fatal("no authorize calls recorded")
			}
			for _, payload := range authorize {
				model, _ := payload["model"].(string)
				policy, _ := payload["provider"].(map[string]any)
				if policy == nil || policy["jurisdiction"] != providerJurisdictionUS {
					t.Fatalf("%s authorized without the US pin: %#v", model, payload["provider"])
				}
				only, _ := policy["only"].([]any)
				want := longContextComboProviders[model]
				if len(only) != len(want) {
					t.Fatalf("%s provider.only = %#v, want %#v", model, only, want)
				}
				for i := range want {
					if only[i] != want[i] {
						t.Fatalf("%s provider.only = %#v, want %#v", model, only, want)
					}
				}
			}
		})
	}
}
