package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const stageDTerminalGoldenCreated = "1767225600"

var (
	stageDChatFixtureID = regexp.MustCompile(`"id":"chatcmpl-[0-9a-f]{32}"`)
	stageDCreatedField  = regexp.MustCompile(`"created":[0-9]+`)
)

type stageDTerminalOrderConn struct {
	mu      sync.Mutex
	settled *atomic.Bool
	body    bytes.Buffer
}

func (w *stageDTerminalOrderConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"tr_finish_reason":`)) && !w.settled.Load() {
		return 0, errors.New("terminal written before settle")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}

func (w *stageDTerminalOrderConn) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

type stageDRoundTripFunc func(*http.Request) (*http.Response, error)

func (f stageDRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func enclaveStageDFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "internal", "trustedrouter", "testdata", "stage_d", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func enclaveStageDLocalFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "stage_d", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func stageDChatTerminalSSE(t *testing.T, raw, reason string) []byte {
	t.Helper()
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	markerIndex := bytes.Index(body, []byte(`"tr_finish_reason":"`+reason+`"`))
	if markerIndex < 0 {
		t.Fatalf("terminal reason %q absent from SSE:\n%s", reason, body)
	}
	start := bytes.LastIndex(body[:markerIndex], []byte("data: "))
	if start < 0 {
		t.Fatalf("terminal SSE block absent before reason %q", reason)
	}
	terminal := append([]byte(nil), body[start:]...)
	terminal = stageDChatFixtureID.ReplaceAll(terminal, []byte(`"id":"chatcmpl_stage_d"`))
	terminal = stageDCreatedField.ReplaceAll(terminal, []byte(`"created":`+stageDTerminalGoldenCreated))
	terminal = bytes.ReplaceAll(terminal, []byte(`"model":"model"`), []byte(`"model":"fixture-model"`))
	return terminal
}

func assertEnclaveStageDTerminalFixture(t *testing.T, name string, got []byte) {
	t.Helper()
	want := enclaveStageDLocalFixture(t, name)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from literal fixture\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

func TestStageDTerminalFixturesMatchAdapterAuthoritativeCopies(t *testing.T) {
	for _, name := range []string{
		"chat_cap.sse",
		"chat_heartbeat_lost.sse",
		"responses_cap_text.sse",
		"responses_cap_reasoning.sse",
		"responses_cap_function_call.sse",
		"responses_cap_mixed.sse",
		"responses_heartbeat_lost.sse",
	} {
		t.Run(name, func(t *testing.T) {
			local := enclaveStageDLocalFixture(t, name)
			authoritative, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapter", "testdata", "stage_d", name))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(local, authoritative) {
				t.Fatalf("%s differs from adapter fixture", name)
			}
		})
	}
}

func TestStageDFlagsDefaultOffAndCohortGate(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "")
	config := stageDConfigFromEnv()
	auth := &trustedrouter.Authorization{StageD: trustedrouter.StageDEligibility{Eligible: true}}
	req := &types.OpenAIChatRequest{Stream: true}
	if config.usageHeartbeat || config.terminateAtCap || stageDStreamEligible(config, auth, req, "chat.completions") {
		t.Fatalf("flags-off config activated Stage D: %#v", config)
	}
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	config = stageDConfigFromEnv()
	for _, test := range []struct {
		route                        string
		stream, routerEligible, want bool
	}{
		{"chat.completions", true, true, true}, {"responses", true, true, true},
		{"messages", true, true, false}, {"chat.completions", false, true, false},
		{"chat.completions", true, false, false},
	} {
		auth.StageD.Eligible, req.Stream = test.routerEligible, test.stream
		if got := stageDStreamEligible(config, auth, req, test.route); got != test.want {
			t.Fatalf("route=%s stream=%t eligible=%t got=%t", test.route, test.stream, test.routerEligible, got)
		}
	}
}

func TestStageDKillSwitchesAreInConfidentialSpaceAllowlists(t *testing.T) {
	for _, name := range []string{"Dockerfile.enclave.gcp.multi", "Dockerfile.enclave.gcp.anthropic"} {
		body, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, flag := range []string{"QUILL_USAGE_HEARTBEAT", "QUILL_TERMINATE_AT_CAP"} {
			if !bytes.Contains(body, []byte(flag)) {
				t.Fatalf("%s missing %s", name, flag)
			}
		}
	}
}

func TestStageDLostDispositionsIncludeOlderRouterShape(t *testing.T) {
	for _, result := range []*trustedrouter.SettleResult{
		{Disposition: trustedrouter.DispositionReapedSnapshot, Settled: true, AlreadySettled: true},
		{Settled: false, AlreadySettled: true},
	} {
		if !stageDDispositionLost(result) {
			t.Fatalf("not lost: %#v", result)
		}
	}
	if stageDDispositionLost(&trustedrouter.SettleResult{Disposition: trustedrouter.DispositionAlreadyFinalized, Settled: true, AlreadySettled: true}) {
		t.Fatal("ordinary already-finalized settle classified lost")
	}
}

func TestStageDMeterIncludesTextReasoningAndToolArguments(t *testing.T) {
	meter := stageDMeter{promptTokens: 7}
	meter.admit(adapter.StreamDelta{Type: "text_delta", Text: "abcd"})
	meter.admit(adapter.StreamDelta{Type: "thinking_delta", Text: "éé"})
	meter.admit(adapter.StreamDelta{Type: "input_json_delta", Text: `{"x"`})
	if meter.outputTokens() != 3 || meter.reasoningTokens() != 1 || meter.toolArgBytes != 4 {
		t.Fatalf("meter = %#v output=%d reasoning=%d", meter, meter.outputTokens(), meter.reasoningTokens())
	}
	usage := meter.heartbeatUsage()
	if usage.InputTokens != 7 || usage.OutputTokens != 3 || usage.ReasoningTokens != 1 {
		t.Fatalf("heartbeat usage = %#v", usage)
	}
}

func TestStageDTerminalUsageKeepsMeteredReasoningWithoutProviderTerminalUsage(t *testing.T) {
	controller := &stageDController{
		started: time.Now().Add(-time.Second), endpointID: "anthropic/test",
		meter: stageDMeter{promptTokens: 7, semanticBytes: 20, reasoningBytes: 8},
	}
	usage := controller.terminalUsage(adapter.StreamTerminal{
		Result: adapter.StreamResult{Usage: &adapter.StreamUsage{InputTokens: 6}},
	}, "request", "responses", "model", &types.OpenAIChatRequest{}, 0.1)
	if usage.InputTokens != 7 || usage.OutputTokens != 5 || usage.ReasoningTokens != 2 || !usage.UsageEstimated {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestSemanticSlicesAreBoundedAndUTF8Safe(t *testing.T) {
	input := strings.Repeat("a", 255) + "🙂" + strings.Repeat("界", 100)
	slices := adapter.SemanticSlices(input)
	var joined strings.Builder
	for index, slice := range slices {
		if !utf8.ValidString(slice) || len([]byte(slice)) > adapter.MaxMeterChunkTokens*4 {
			t.Fatalf("slice %d invalid or oversized: %d bytes", index, len([]byte(slice)))
		}
		joined.WriteString(slice)
	}
	if joined.String() != input {
		t.Fatal("slices did not reconstruct input")
	}
}

func TestStageDCapChecksBetweenSlices(t *testing.T) {
	controller := &stageDController{
		auth:   &trustedrouter.Authorization{AuthorizationID: "auth"},
		config: stageDConfig{terminateAtCap: true},
		meter:  stageDMeter{}, capMicro: 64, hasPrice: true,
		price:        trustedrouter.CandidatePrice{Rates: trustedrouter.PriceRates{OutputMicroPerMillion: 1_000_000}},
		lastAccepted: time.Now(),
	}
	if err := controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: strings.Repeat("x", 256)}); err != nil {
		t.Fatal(err)
	}
	if err := controller.afterSlice(adapter.StreamDelta{Type: "text_delta", Text: strings.Repeat("x", 256)}); err != nil {
		t.Fatal(err)
	}
	err := controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: "xxxx"})
	termination, ok := err.(*adapter.ControlledTermination)
	if !ok || termination.TRFinishReason != "cap_reached" || controller.meter.outputTokens() != 64 {
		t.Fatalf("termination=%#v meter=%d", termination, controller.meter.outputTokens())
	}
}

func TestStageDHeartbeatCapReplyDoesNotChangeBoundEnforcementCap(t *testing.T) {
	for _, replyCap := range []int64{32, 128} {
		t.Run(fmt.Sprintf("reply_%d", replyCap), func(t *testing.T) {
			gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
				body := fmt.Sprintf(`{"accepted":true,"seq":1,"expires_at_ms":1788307500000,"cap_micro":%d,"running_micro":12}`, replyCap)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})
			controller := &stageDController{
				ctx: t.Context(), gateway: gateway, auth: &trustedrouter.Authorization{AuthorizationID: "auth"},
				config:  stageDConfig{terminateAtCap: true, heartbeatBudget: time.Second},
				started: time.Now(), endpointID: "endpoint", capMicro: 64, hasPrice: true,
				price: trustedrouter.CandidatePrice{Rates: trustedrouter.PriceRates{OutputMicroPerMillion: 1_000_000}},
			}
			controller.mu.Lock()
			err := controller.sendHeartbeatLocked(1)
			controller.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if controller.capMicro != 64 {
				t.Fatalf("reply cap=%d changed bound cap to %d", replyCap, controller.capMicro)
			}

			atCap := adapter.StreamDelta{Type: "text_delta", Text: strings.Repeat("x", 256)}
			if err := controller.beforeSlice(atCap); err != nil {
				t.Fatalf("reply cap=%d terminated below bound cap: %v", replyCap, err)
			}
			if err := controller.afterSlice(atCap); err != nil {
				t.Fatal(err)
			}
			err = controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: "xxxx"})
			termination, ok := err.(*adapter.ControlledTermination)
			if !ok || termination.TRFinishReason != "cap_reached" || controller.meter.outputTokens() != 64 {
				t.Fatalf("reply cap=%d termination=%#v meter=%d", replyCap, termination, controller.meter.outputTokens())
			}
		})
	}
}

func TestStageDUsagePricingUsesHalfUpAndTinyPositiveFloor(t *testing.T) {
	price := trustedrouter.CandidatePrice{}
	rates := trustedrouter.PriceRates{OutputMicroPerMillion: 1}
	if got := stageDUsageMicro(price, rates, 0, 1, 0, 0); got != 1 {
		t.Fatalf("tiny positive=%d", got)
	}
	rates.OutputMicroPerMillion = 500_000
	if got := stageDUsageMicro(price, rates, 0, 1, 0, 0); got != 1 {
		t.Fatalf("half-up=%d", got)
	}
}

func TestDueHeartbeatStallsSliceUntilPinnedAcceptance(t *testing.T) {
	requestSeen := make(chan struct{})
	release := make(chan struct{})
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	client := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{Transport: stageDRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		_, _ = io.ReadAll(request.Body)
		close(requestSeen)
		<-release
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
	})})
	client.ConfigureStageDBoot(signer)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	controller := &stageDController{
		ctx: ctx, gateway: client, auth: &trustedrouter.Authorization{AuthorizationID: "auth"}, cancel: cancel,
		config: stageDConfig{heartbeatBudget: time.Second}, started: time.Now(), endpointID: "endpoint",
		lastAccepted: time.Now().Add(-stageDHeartbeatInterval - time.Second),
	}
	done := make(chan error, 1)
	go func() { done <- controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: "abcd"}) }()
	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not sent")
	}
	select {
	case err := <-done:
		t.Fatalf("slice escaped before acceptance: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := controller.afterSlice(adapter.StreamDelta{Type: "text_delta", Text: "abcd"}); err != nil {
		t.Fatal(err)
	}
	if controller.meter.outputTokens() != 1 {
		t.Fatalf("meter=%d", controller.meter.outputTokens())
	}
}

func TestStageDHeartbeatLossRefusesEveryLaterSlice(t *testing.T) {
	var heartbeatCount atomic.Int32
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != trustedrouter.HeartbeatPath {
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
		if heartbeatCount.Add(1) == 1 {
			return &http.Response{
				StatusCode: 409, Header: make(http.Header), Request: request,
				Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "rejection_stale_seq.json"))),
			}, nil
		}
		return &http.Response{
			StatusCode: 200, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))),
		}, nil
	})
	controller := newStageDController(
		t.Context(), gateway, stageDStreamingAuthorization(), nil, nil,
		stageDConfig{heartbeatBudget: time.Second}, time.Now(), "anthropic/test", 0,
	)
	controller.lastAccepted = time.Now().Add(-stageDHeartbeatInterval - time.Second)

	first := controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: "first"})
	firstTermination, ok := first.(*adapter.ControlledTermination)
	if !ok || firstTermination.TRFinishReason != "heartbeat_lost" || !controller.heartbeatLost {
		t.Fatalf("first rejection=%#v heartbeat_lost=%t", first, controller.heartbeatLost)
	}
	meterBefore := controller.meter

	second := controller.beforeSlice(adapter.StreamDelta{Type: "text_delta", Text: "later delta"})
	secondTermination, ok := second.(*adapter.ControlledTermination)
	if !ok || secondTermination.TRFinishReason != "heartbeat_lost" {
		t.Fatalf("later slice termination = %#v", second)
	}
	if controller.sliceInFlight || controller.meter != meterBefore || heartbeatCount.Load() != 1 {
		t.Fatalf(
			"later slice admitted: in_flight=%t meter=%#v before=%#v heartbeats=%d",
			controller.sliceInFlight, controller.meter, meterBefore, heartbeatCount.Load(),
		)
	}
}

func TestStageDControllerPreHeaderSendsPinnedHeartbeatBytes(t *testing.T) {
	want := enclaveStageDLocalFixture(t, "heartbeat_request.json")
	var wireBody []byte
	var wireReadErr error
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != trustedrouter.HeartbeatPath {
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
		wireBody, wireReadErr = io.ReadAll(request.Body)
		return &http.Response{
			StatusCode: 200, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))),
		}, nil
	})
	started := time.UnixMilli(1788307200000)
	controller := newStageDController(
		t.Context(), gateway, stageDStreamingAuthorization(), nil, nil,
		stageDConfig{heartbeatBudget: time.Second}, started, "anthropic/test", 100,
	)
	controller.now = func() time.Time { return started.Add(time.Second) }
	controller.meter.semanticBytes = 40
	if err := controller.preHeader(); err != nil {
		t.Fatal(err)
	}
	controller.stopCadence()

	if wireReadErr != nil {
		t.Fatal(wireReadErr)
	}
	if !bytes.Equal(wireBody, want) {
		t.Fatalf("controller heartbeat wire bytes differ\ngot:  %s\nwant: %s", wireBody, want)
	}
}

func TestChatControlBlocksAllOutputBeforeFirstSliceAcceptance(t *testing.T) {
	provider := strings.NewReader("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	entered := make(chan struct{})
	release := make(chan struct{})
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := adapter.TransformStreamCaptureControlled(provider, &output, "id", "model", false, nil, nil, &adapter.StreamControl{BeforeSlice: func(adapter.StreamDelta) error {
			close(entered)
			<-release
			return nil
		}})
		done <- err
	}()
	<-entered
	if output.Len() != 0 {
		t.Fatalf("output before acceptance = %q", output.String())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "hello") {
		t.Fatalf("output=%s", output.String())
	}
}

func stageDStreamingAuthorization() *trustedrouter.Authorization {
	return &trustedrouter.Authorization{
		AuthorizationID: "gwa-stage-d-fixture", Model: "model", EndpointID: "anthropic/test",
		StageD: trustedrouter.StageDEligibility{Eligible: true, Reason: "ok"}, CapMicro: 300,
		CandidatePrices: []trustedrouter.CandidatePrice{{
			EndpointID: "anthropic/test",
			Rates:      trustedrouter.PriceRates{InputMicroPerMillion: 1_000_000, OutputMicroPerMillion: 2_000_000},
			Rounding:   "half_up_per_million",
		}},
		RouteType: "chat.completions",
	}
}

func stageDStreamingGateway(t *testing.T, transport stageDRoundTripFunc) *trustedrouter.Client {
	t.Helper()
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	client := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{Transport: transport})
	client.ConfigureStageDBoot(signer)
	return client
}

func TestServeStreamingStageDPreHeaderWaitsForHeartbeatAcceptance(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	provider := &blockingFirstByteClient{started: make(chan struct{}), release: make(chan struct{})}
	heartbeatSeen := make(chan struct{})
	heartbeatRelease := make(chan struct{})
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case trustedrouter.HeartbeatPath:
			close(heartbeatSeen)
			<-heartbeatRelease
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
		case "/internal/gateway/settle":
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "settle_response_intent_durable.json"))), Request: request}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	out := &synchronizedBuffer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveStreaming(t.Context(), out, provider,
			&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
			[]llm.InvokeOptions{{Model: "model", Provider: "anthropic", EndpointID: "anthropic/test"}},
			gateway, stageDStreamingAuthorization(), nil, time.Now(), nil, "chat.completions", "stage-d-preheader", "model")
	}()
	<-provider.started
	if out.Len() != 0 {
		t.Fatalf("bytes before provider route = %d", out.Len())
	}
	close(provider.release)
	select {
	case <-heartbeatSeen:
	case <-time.After(time.Second):
		t.Fatal("heartbeat not sent")
	}
	if out.Len() != 0 {
		t.Fatalf("bytes before heartbeat acceptance = %d", out.Len())
	}
	close(heartbeatRelease)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not finish")
	}
	if body := out.String(); !strings.Contains(body, "HTTP/1.1 200 OK") || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("body=%s", body)
	}
}

func TestServeStreamingStageDPreHeaderRejectionHasNoSuccessOrProviderBytes(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 409, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "rejection_out_of_cohort.json"))), Request: request}, nil
	})
	var out bytes.Buffer
	serveStreaming(t.Context(), &out, provider,
		&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
		time.Now(), nil, "chat.completions", "stage-d-reject", "model")
	body := out.String()
	if strings.Contains(body, "HTTP/1.1 200") || strings.Contains(body, `"content":"ok"`) || !strings.Contains(body, "503") {
		t.Fatalf("preheader rejection body=%s", body)
	}
}

func TestServeStreamingStageDSettlesBeforeTerminalForEveryDisposition(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	for _, disposition := range []string{
		trustedrouter.DispositionFinalized, trustedrouter.DispositionIntentDurable,
		trustedrouter.DispositionAlreadyFinalized, trustedrouter.DispositionReapedSnapshot,
	} {
		t.Run(disposition, func(t *testing.T) {
			var settled atomic.Bool
			gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case trustedrouter.HeartbeatPath:
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
				case "/internal/gateway/settle":
					settled.Store(true)
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "settle_response_"+disposition+".json"))), Request: request}, nil
				default:
					return nil, errors.New("unexpected path: " + request.URL.Path)
				}
			})
			provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
				_, err := io.WriteString(out, providerStreamTestResponse)
				return err
			}}
			conn := &stageDTerminalOrderConn{settled: &settled}
			serveStreaming(t.Context(), conn, provider,
				&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
				[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
				time.Now(), nil, "chat.completions", "stage-d-settle", "model")
			if !settled.Load() || !strings.Contains(conn.String(), "data: [DONE]") {
				t.Fatalf("settled=%t body=%s", settled.Load(), conn.String())
			}
		})
	}
}

func TestServeStreamingStageDClassifiesReapedSnapshotAsSettleLostAndCompletes(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	var settleCount atomic.Int32
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case trustedrouter.HeartbeatPath:
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
		case "/internal/gateway/settle":
			settleCount.Add(1)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "settle_response_reaped_snapshot.json"))), Request: request}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	var out bytes.Buffer
	logs := captureProviderStreamStderr(t, func() {
		serveStreaming(t.Context(), &out, provider,
			&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
			[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
			time.Now(), nil, "chat.completions", "stage-d-reaped-snapshot", "model")
	})

	if settleCount.Load() != 1 {
		t.Fatalf("settle calls = %d, want 1", settleCount.Load())
	}
	if !strings.Contains(logs, `enclave.stage_d_settle_lost auth_id="gwa-stage-d-fixture" disposition="reaped_snapshot" source="settle"`) {
		t.Fatalf("reaped snapshot was not classified as a lost settlement; logs=%q", logs)
	}
	if body := out.String(); !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("terminal event did not complete; body=%s", body)
	}
}

func TestServeStreamingStageDSettleTimeoutLooksUpDispositionThenTerminates(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "10")
	var settled atomic.Bool
	var lookup atomic.Bool
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.Path == trustedrouter.HeartbeatPath:
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
		case request.URL.Path == "/internal/gateway/settle":
			<-request.Context().Done()
			return nil, request.Context().Err()
		case strings.HasSuffix(request.URL.Path, "/disposition"):
			lookup.Store(true)
			settled.Store(true)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "disposition_lookup_response.json"))), Request: request}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	conn := &stageDTerminalOrderConn{settled: &settled}
	serveStreaming(t.Context(), conn, provider,
		&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
		time.Now(), nil, "chat.completions", "stage-d-timeout", "model")
	if !lookup.Load() || !strings.Contains(conn.String(), "data: [DONE]") {
		t.Fatalf("lookup=%t body=%s", lookup.Load(), conn.String())
	}
}

func TestServeStreamingStageDDueHeartbeatFailureSettlesPartialAndCloses(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	var heartbeatCount atomic.Int32
	var settled atomic.Bool
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case trustedrouter.HeartbeatPath:
			if heartbeatCount.Add(1) == 1 {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
			}
			return &http.Response{StatusCode: 409, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "rejection_stale_seq.json"))), Request: request}, nil
		case "/internal/gateway/settle":
			settled.Store(true)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "settle_response_intent_durable.json"))), Request: request}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	semantic := strings.Repeat("x", 1100)
	providerWire := fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%q}}\n\n", semantic)
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerWire)
		return err
	}}
	conn := &stageDTerminalOrderConn{settled: &settled}
	serveStreaming(t.Context(), conn, provider,
		&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
		time.Now(), nil, "chat.completions", "stage-d-lost", "model")
	body := conn.String()
	if heartbeatCount.Load() != 2 || !settled.Load() || !strings.Contains(body, `"tr_finish_reason":"heartbeat_lost"`) {
		t.Fatalf("heartbeats=%d settled=%t body=%s", heartbeatCount.Load(), settled.Load(), body)
	}
	assertEnclaveStageDTerminalFixture(t, "chat_heartbeat_lost.sse", stageDChatTerminalSSE(t, body, "heartbeat_lost"))
}

func TestServeStreamingStageDCapSettlesMeteredPartialBeforeTerminal(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "on")
	var settled atomic.Bool
	var settledOutput int
	gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case trustedrouter.HeartbeatPath:
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "heartbeat_response_accepted.json"))), Request: request}, nil
		case "/internal/gateway/settle":
			var payload map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			settledOutput = int(payload["actual_output_tokens"].(float64))
			settled.Store(true)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, "settle_response_intent_durable.json"))), Request: request}, nil
		default:
			return nil, errors.New("unexpected path: " + request.URL.Path)
		}
	})
	providerWire := fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%q}}\n\n", strings.Repeat("x", 800))
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerWire)
		return err
	}}
	conn := &stageDTerminalOrderConn{settled: &settled}
	serveStreaming(t.Context(), conn, provider,
		&types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil,
		time.Now(), nil, "chat.completions", "stage-d-cap", "model")
	body := conn.String()
	if !settled.Load() || settledOutput != 128 || !strings.Contains(body, `"finish_reason":"length"`) || !strings.Contains(body, `"tr_finish_reason":"cap_reached"`) {
		t.Fatalf("settled=%t output=%d body=%s", settled.Load(), settledOutput, body)
	}
	assertEnclaveStageDTerminalFixture(t, "chat_cap.sse", stageDChatTerminalSSE(t, body, "cap_reached"))
}

func TestStageDRetryJobsConsumePinnedLostDispositions(t *testing.T) {
	for _, kind := range []string{"settle", "refund"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			gateway := stageDStreamingGateway(t, func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				wantPath := "/internal/gateway/" + kind
				if request.URL.Path != wantPath {
					t.Fatalf("path=%s want=%s", request.URL.Path, wantPath)
				}
				return &http.Response{
					StatusCode: 200, Header: make(http.Header), Request: request,
					Body: io.NopCloser(bytes.NewReader(enclaveStageDFixture(t, kind+"_response_reaped_snapshot.json"))),
				}, nil
			})
			queue := &settlementRetryQueue{
				jobs: make(chan settlementRetryJob, 1), maxAttempts: 2,
			}
			job := settlementRetryJob{
				trGateway: gateway, authorization: stageDStreamingAuthorization(),
				requestLogID: "stage-d-retry", enqueuedAt: time.Now(), kind: kind,
				refundStatus: 502, refundType: "provider_error", refundElapsed: 0.1,
			}
			queue.process(context.Background(), job)
			if calls.Load() != 1 || len(queue.jobs) != 0 {
				t.Fatalf("calls=%d queued=%d", calls.Load(), len(queue.jobs))
			}
		})
	}
}
