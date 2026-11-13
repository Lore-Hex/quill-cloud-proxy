package main

import (
	"bufio"
	"context"
	"encoding/json"
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

func TestLiberty41IsLiberty40PlusInkling2SmallOnThePanel(t *testing.T) {
	if _, ok := advisorPresetForModel(trustedRouterLiberty41Model); ok {
		t.Fatal("Liberty 4.1 must be a fusion, not an advisor combo")
	}
	if !isFusionModel(trustedRouterLiberty41Model) {
		t.Fatal("Liberty 4.1 must be a fusion model")
	}
	preset, panel, ok := fusionPresetPanelForModel(trustedRouterLiberty41Model)
	wantPanel := []string{fusionNemotron3Ultra, "reflection/beam-1.0", "meta-models/muse-spark-open", fusionInkling2Small}
	if !ok || preset != "liberty-4.1" || !reflect.DeepEqual(panel, wantPanel) {
		t.Fatalf("panel = %q %#v, want liberty-4.1 %#v", preset, panel, wantPanel)
	}
	// The fusers and their order are Liberty 4.0's; Inkling 2 Small only answers.
	wantFusers := []string{"meta-models/muse-spark-open", "reflection/beam-1.0", fusionNemotron3Ultra}
	judges, err := fusionJudgeModels(fusionConfig{}, trustedRouterLiberty41Model)
	if err != nil || !reflect.DeepEqual(judges, wantFusers) {
		t.Fatalf("judge models = %#v (%v), want %#v", judges, err, wantFusers)
	}
	finals, err := fusionFinalModels(fusionConfig{}, trustedRouterLiberty41Model, panel[0])
	if err != nil || !reflect.DeepEqual(finals, wantFusers) {
		t.Fatalf("final models = %#v (%v), want %#v", finals, err, wantFusers)
	}

	config, requested, err := fusionConfigForRequest(&types.OpenAIChatRequest{Model: trustedRouterLiberty41Model})
	if err != nil || !requested {
		t.Fatalf("fusionConfigForRequest: requested=%v err=%v", requested, err)
	}
	if config.ProviderJurisdiction != providerJurisdictionUS {
		t.Fatalf("provider jurisdiction = %q, want US", config.ProviderJurisdiction)
	}
	if !config.FuserFailover {
		t.Fatal("Liberty 4.1 fusers must fail over on provider errors")
	}

	if !isLongContextCombo(trustedRouterLiberty41Model) {
		t.Fatal("Liberty 4.1 members must be pinned to their matched-window routes")
	}
	for _, member := range append(append([]string(nil), panel...), wantFusers...) {
		if len(longContextComboProviders[member]) == 0 {
			t.Fatalf("no reviewed matched-window route for %s", member)
		}
	}
	// Inkling 2 Small's only reviewed route is Cloudflare's US 1M one. Nebius
	// is not US-headquartered, Tinker serves 256K, and DeepInfra is barred
	// from every combo.
	if got := longContextComboProviders[fusionInkling2Small]; !reflect.DeepEqual(got, []string{"cloudflare-workers-ai"}) {
		t.Fatalf("Inkling 2 Small routes = %#v, want only cloudflare-workers-ai", got)
	}
	if _, short := fusionShortWindowMembers[fusionInkling2Small]; short {
		t.Fatal("Inkling 2 Small serves 1M on its reviewed route and must not be dropped for length")
	}
	for member, providers := range longContextComboProviders {
		for _, provider := range providers {
			if provider == "deepinfra" {
				t.Fatalf("%s may route to DeepInfra, which every combo excludes", member)
			}
		}
	}

	// Liberty 4.0 keeps its three-member panel.
	_, panel40, _ := fusionPresetPanelForModel(trustedRouterLiberty40Model)
	if want := []string{fusionNemotron3Ultra, "reflection/beam-1.0", "meta-models/muse-spark-open"}; !reflect.DeepEqual(panel40, want) {
		t.Fatalf("Liberty 4.0 panel = %#v, want unchanged %#v", panel40, want)
	}
}

func TestLiberty41CallsEveryMemberOnItsUSRouteThroughLocalGateway(t *testing.T) {
	trGateway, recorder, closeGateway := newFusionGatewayRecorder(t)
	defer closeGateway()
	streamer := &fusionEchoLLM{failModels: map[string]bool{"meta-models/muse-spark-open": true}}
	status, body := postLibertyModelContent(t, trGateway, streamer, trustedRouterLiberty41Model, "Reply with a short local test answer.")
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%s", status, body)
	}
	if !strings.Contains(body, "final answer from reflection/beam-1.0") {
		t.Fatalf("Beam must take over fusing when Muse Spark is down: %s", body)
	}
	streamer.mu.Lock()
	gotCalls := map[string]int{}
	for _, call := range streamer.calls {
		gotCalls[call.Model]++
	}
	streamer.mu.Unlock()
	// Inkling 2 Small answers once on the panel and never fuses.
	want := map[string]int{"meta-models/muse-spark-open": 3, "reflection/beam-1.0": 3, fusionNemotron3Ultra: 1, fusionInkling2Small: 1}
	if !reflect.DeepEqual(gotCalls, want) {
		t.Fatalf("calls per model = %#v, want %#v", gotCalls, want)
	}

	recorder.mu.Lock()
	authorize := append([]map[string]any(nil), recorder.authorize...)
	recorder.mu.Unlock()
	sawInkling := false
	for _, payload := range authorize {
		model, _ := payload["model"].(string)
		policy, _ := payload["provider"].(map[string]any)
		if policy == nil || policy["jurisdiction"] != providerJurisdictionUS {
			t.Fatalf("%s authorized without the US pin: %#v", model, payload["provider"])
		}
		only, _ := policy["only"].([]any)
		wantOnly := longContextComboProviders[model]
		if len(only) != len(wantOnly) {
			t.Fatalf("%s provider.only = %#v, want %#v", model, only, wantOnly)
		}
		for i := range wantOnly {
			if only[i] != wantOnly[i] {
				t.Fatalf("%s provider.only = %#v, want %#v", model, only, wantOnly)
			}
		}
		if model == fusionInkling2Small {
			sawInkling = true
		}
	}
	if !sawInkling {
		t.Fatal("Inkling 2 Small was never authorized")
	}
}

func TestLiberty41LongRequestsKeepInkling2SmallAndDropOnlyUltra(t *testing.T) {
	trGateway, _, closeGateway := newFusionGatewayRecorder(t)
	defer closeGateway()
	streamer := &fusionEchoLLM{}
	// ~225K estimated tokens: past Ultra's 256K routes once the panel budget is
	// added, well inside Inkling 2 Small's 1M one.
	status, body := postLibertyModelContent(t, trGateway, streamer, trustedRouterLiberty41Model, strings.Repeat("a", 900_000))
	streamer.mu.Lock()
	called := map[string]int{}
	for _, call := range streamer.calls {
		called[call.Model]++
	}
	streamer.mu.Unlock()
	if status != http.StatusOK || called[fusionNemotron3Ultra] != 0 || called[fusionInkling2Small] != 1 || called["reflection/beam-1.0"] == 0 {
		t.Fatalf("status=%d calls=%#v body=%.300s", status, called, body)
	}
}

func postLibertyModelContent(t *testing.T, trGateway *trustedrouter.Client, streamer *fusionEchoLLM, model, content string) (int, string) {
	t.Helper()
	serverConn, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveOne(context.Background(), serverConn, auth.New(nil), streamer, nil, nil, trGateway, nil)
	}()
	requestBody, err := json.Marshal(map[string]any{
		"model":      model,
		"stream":     false,
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
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	<-done
	return resp.StatusCode, string(respBody)
}
