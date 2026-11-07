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
	"net/url"
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
	wantPanel := []string{fusionNemotron3Ultra, "reflection/beam-1.0", "meta-models/muse-spark-open"}
	if !ok || preset != "liberty-4.0" || !reflect.DeepEqual(panel, wantPanel) {
		t.Fatalf("panel = %q %#v, want liberty-4.0 %#v", preset, panel, wantPanel)
	}
	wantFusers := []string{"meta-models/muse-spark-open", "reflection/beam-1.0", fusionNemotron3Ultra}
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
	refunded := &fusionRefundedProviderError{err: providerErr}
	// A metered partial generation is settled, not refunded, so it comes back
	// unwrapped; a queued settle comes back as settlementAttemptedError.
	settleQueued := &settlementAttemptedError{err: errors.New("settle: connection reset by peer")}
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
		{"refunded provider error stops without failover", context.Background(), fusionConfig{}, refunded, false},
		{"refunded provider error falls through with failover", context.Background(), on, refunded, true},
		{"partially billed provider error stops even with failover", context.Background(), on, providerErr, false},
		{"queued settle stops even with failover", context.Background(), on, settleQueued, false},
		{"control-plane refusal stops even with failover", context.Background(), on, balanceErr, false},
		{"canceled request stops even with failover", canceled, on, refunded, false},
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
			// Muse Spark fails on the panel, as judge and as final; Beam answers
			// on the panel, then takes over as judge and final.
			wantCalls: map[string]int{"meta-models/muse-spark-open": 3, "reflection/beam-1.0": 3, fusionNemotron3Ultra: 1},
		},
		{
			name:       "Muse Spark down while streaming: Beam fuses",
			stream:     true,
			failModels: map[string]bool{"meta-models/muse-spark-open": true},
			wantFinal:  "reflection/beam-1.0",
			wantCalls:  map[string]int{"meta-models/muse-spark-open": 3, "reflection/beam-1.0": 3, fusionNemotron3Ultra: 1},
		},
		{
			name: "Muse Spark and Beam down: Nemotron's lone panel answer is fused by Nemotron",
			failModels: map[string]bool{
				"meta-models/muse-spark-open": true,
				"reflection/beam-1.0":         true,
			},
			wantFinal: fusionNemotron3Ultra,
			wantCalls: map[string]int{"meta-models/muse-spark-open": 3, "reflection/beam-1.0": 3, fusionNemotron3Ultra: 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trGateway, recorder, closeGateway := newFusionGatewayRecorder(t)
			defer closeGateway()
			streamer := &fusionEchoLLM{failModels: tt.failModels}
			status, body := postLiberty40(t, trGateway, streamer, tt.stream)
			if status != http.StatusOK {
				t.Fatalf("status = %d body=%s", status, body)
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

func TestLiberty40StopsTheFuserChainWhenAFuserMayAlreadyBeBilled(t *testing.T) {
	// Muse Spark answers as judge, but its settle is lost on the wire, so the
	// gateway queues it for retry: the user will be billed for that answer.
	// Handing the judge to Beam would bill the same work twice.
	trGateway, recorder, closeGateway := newFusionGatewayRecorder(t)
	defer closeGateway()
	recorder.dropSettleModels = map[string]bool{"meta-models/muse-spark-open": true}
	streamer := &fusionEchoLLM{}
	status, body := postLiberty40(t, trGateway, streamer, false)
	if status == http.StatusOK {
		t.Fatalf("status = 200, want the chain to stop after the queued settle: %s", body)
	}
	streamer.mu.Lock()
	gotCalls := map[string]int{}
	for _, call := range streamer.calls {
		gotCalls[call.Model]++
	}
	streamer.mu.Unlock()
	// Muse Spark sits on the panel and is the first judge; nothing runs after.
	want := map[string]int{"meta-models/muse-spark-open": 2, "reflection/beam-1.0": 1, fusionNemotron3Ultra: 1}
	if !reflect.DeepEqual(gotCalls, want) {
		t.Fatalf("calls per model = %#v, want the panel plus Muse Spark's judge only %#v", gotCalls, want)
	}
}

func postLiberty40(t *testing.T, trGateway *trustedrouter.Client, streamer *fusionEchoLLM, stream bool) (int, string) {
	t.Helper()
	return postLiberty40Content(t, trGateway, streamer, stream, "Reply with a short local test answer.")
}

func postLiberty40Content(t *testing.T, trGateway *trustedrouter.Client, streamer *fusionEchoLLM, stream bool, content string) (int, string) {
	t.Helper()
	serverConn, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)
	}()
	requestBody, err := json.Marshal(map[string]any{
		"model":      trustedRouterLiberty40Model,
		"stream":     stream,
		"messages":   []map[string]any{{"role": "user", "content": content}},
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
	return resp.StatusCode, string(body)
}

func TestErrorTypeChainSkipsBillingMarkers(t *testing.T) {
	inner := &url.Error{Op: "Post", URL: "https://provider.test", Err: errors.New("boom")}
	for _, err := range []error{
		&fusionRefundedProviderError{err: inner},
		&settlementAttemptedError{err: inner},
	} {
		if got, want := errorTypeChain(err), errorTypeChain(inner); got != want {
			t.Fatalf("errorTypeChain(%T) = %q, want %q", err, got, want)
		}
	}
}

func TestLiberty40DropsNemotronUltraWhenThePromptOverrunsItsWindow(t *testing.T) {
	_, panel, _ := fusionPresetPanelForModel(trustedRouterLiberty40Model)
	message := func(chars int) []types.OpenAIChatMessage {
		return []types.OpenAIChatMessage{{Role: "user", Content: strings.Repeat("a", chars)}}
	}
	// ~200K estimated tokens + 32,768 reserved + 8,000 margin fits 262,144.
	if got := fusionWithoutOverlongMembers(panel, message(800_000)); !reflect.DeepEqual(got, panel) {
		t.Fatalf("short prompt panel = %#v, want all of %#v", got, panel)
	}
	// ~225K estimated tokens does not, so only the 1M members answer.
	want := []string{"reflection/beam-1.0", "meta-models/muse-spark-open"}
	if got := fusionWithoutOverlongMembers(panel, message(900_000)); !reflect.DeepEqual(got, want) {
		t.Fatalf("long prompt panel = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(panel, fusionLiberty40Panel) {
		t.Fatal("dropping a member must not mutate the preset")
	}
	// A list made only of short-window models is never emptied.
	only := []string{fusionNemotron3Ultra}
	if got := fusionWithoutOverlongMembers(only, message(900_000)); !reflect.DeepEqual(got, only) {
		t.Fatalf("all-short list = %#v, want %#v", got, only)
	}

	// End to end: a long request reaches only the 1M members, and Ultra is
	// not tried as a fuser either, even when both 1M fusers fail.
	for _, tt := range []struct {
		name       string
		failModels map[string]bool
	}{
		{"healthy", nil},
		{"Muse Spark and Beam down", map[string]bool{"meta-models/muse-spark-open": true, "reflection/beam-1.0": true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trGateway, _, closeGateway := newFusionGatewayRecorder(t)
			defer closeGateway()
			streamer := &fusionEchoLLM{failModels: tt.failModels}
			status, body := postLiberty40Content(t, trGateway, streamer, false, strings.Repeat("a", 900_000))
			streamer.mu.Lock()
			defer streamer.mu.Unlock()
			called := map[string]int{}
			for _, call := range streamer.calls {
				called[call.Model]++
			}
			if called[fusionNemotron3Ultra] != 0 || called["reflection/beam-1.0"] == 0 {
				t.Fatalf("status=%d calls per model = %#v, want the 1M members without Nemotron Ultra; body=%.300s", status, called, body)
			}
			if tt.failModels == nil && status != http.StatusOK {
				t.Fatalf("status = %d body=%.300s", status, body)
			}
		})
	}
}

func TestLiberty40DropsNemotronUltraAsFuserWhenThePromptOverrunsItsWindow(t *testing.T) {
	long := []types.OpenAIChatMessage{{Role: "user", Content: strings.Repeat("a", 900_000)}}
	short := []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}
	fusers := append([]string(nil), fusionLiberty40Fusers...)
	want1M := []string{"meta-models/muse-spark-open", "reflection/beam-1.0"}

	finals, judges := fusionBuiltInFusersThatFit(fusionConfig{}, long, fusers, fusers)
	if !reflect.DeepEqual(finals, want1M) || !reflect.DeepEqual(judges, want1M) {
		t.Fatalf("long prompt fusers = %#v / %#v, want %#v", finals, judges, want1M)
	}
	finals, judges = fusionBuiltInFusersThatFit(fusionConfig{}, short, fusers, fusers)
	if !reflect.DeepEqual(finals, fusers) || !reflect.DeepEqual(judges, fusers) {
		t.Fatalf("short prompt fusers = %#v / %#v, want all of %#v", finals, judges, fusers)
	}
	// A caller's explicit fuser lists are theirs to keep.
	explicit := fusionConfig{FinalModels: fusers, JudgeModels: fusers}
	finals, judges = fusionBuiltInFusersThatFit(explicit, long, fusers, fusers)
	if !reflect.DeepEqual(finals, fusers) || !reflect.DeepEqual(judges, fusers) {
		t.Fatalf("explicit fusers = %#v / %#v, want untouched %#v", finals, judges, fusers)
	}
	if !reflect.DeepEqual(fusionLiberty40Fusers, fusers) {
		t.Fatal("dropping a fuser must not mutate the preset")
	}
}
