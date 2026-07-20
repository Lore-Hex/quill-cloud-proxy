package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/websearch"
)

type fakeResponsesWebSearchRunner struct {
	results  []fusionCallResult
	errors   []error
	requests []*types.OpenAIChatRequest
	routes   []string
	calls    int
}

type webSearchScriptedLLM struct{}

func (webSearchScriptedLLM) InvokeStreaming(
	_ context.Context,
	req *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	for _, message := range req.Messages {
		if message.Role == "tool" && message.ToolCallID == "call_tool" {
			return writeAnthropicTextTestStream(out, req.Model, "The release is live at https://example.com/release")
		}
	}
	return writeAnthropicToolUseArgsTestStream(out, adapter.TrustedRouterWebSearchFunction, `{"query":"trusted router release"}`)
}

func (runner *fakeResponsesWebSearchRunner) Run(
	_ context.Context,
	req *types.OpenAIChatRequest,
	routeType string,
	_ string,
	observer adapter.StreamObserver,
	validate func(adapter.StreamResult) error,
	_ bool,
) (fusionCallResult, error) {
	index := runner.calls
	runner.calls++
	runner.routes = append(runner.routes, routeType)
	if index < len(runner.errors) && runner.errors[index] != nil {
		return fusionCallResult{}, runner.errors[index]
	}
	if index >= len(runner.results) {
		return fusionCallResult{}, errors.New("unexpected model call")
	}
	result := runner.results[index]
	if validate != nil {
		if err := validate(result.Result); err != nil {
			return fusionCallResult{}, err
		}
	}
	runner.requests = append(runner.requests, cloneChatRequest(req))
	if observer != nil {
		for _, block := range result.Result.Thinking {
			observer(adapter.StreamDelta{Type: "thinking_delta", Text: block.Text})
		}
		if result.Result.Text != "" {
			observer(adapter.StreamDelta{Type: "text_delta", Text: result.Result.Text})
		}
	}
	return result, nil
}

type fakeResponsesWebSearcher struct {
	results []websearch.Result
	errors  []error
	queries []string
	options []websearch.SearchOptions
}

func (searcher *fakeResponsesWebSearcher) Search(_ context.Context, query string, options websearch.SearchOptions) (websearch.Result, error) {
	index := len(searcher.queries)
	searcher.queries = append(searcher.queries, query)
	searcher.options = append(searcher.options, options)
	if index < len(searcher.errors) && searcher.errors[index] != nil {
		return websearch.Result{}, searcher.errors[index]
	}
	if index >= len(searcher.results) {
		return websearch.Result{}, errors.New("unexpected search call")
	}
	return searcher.results[index], nil
}

func webSearchTestRequest() *types.OpenAIChatRequest {
	return &types.OpenAIChatRequest{
		Model:    "test/model",
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "What changed today?"}},
		Tools: []any{map[string]any{
			"type": "function",
			"function": map[string]any{
				"name": adapter.TrustedRouterWebSearchFunction,
			},
		}},
		Response: &types.ResponseRequestMeta{
			WebSearch: &types.ResponseWebSearchConfig{SearchContextSize: "low", MaxCalls: 1, IncludeSources: true},
		},
	}
}

func webSearchPlannerCall(query string) fusionCallResult {
	return fusionCallResult{
		Result: adapter.StreamResult{
			ToolCalls: []types.ToolCall{{
				ID:        "call_internal_1",
				CallID:    "call_internal_1",
				Name:      adapter.TrustedRouterWebSearchFunction,
				Arguments: `{"query":` + mustJSONString(query) + `}`,
			}},
			Usage: &adapter.StreamUsage{InputTokens: 11, OutputTokens: 3},
		},
		Model:            "planner/model",
		InputTokens:      11,
		OutputTokens:     3,
		SettlementResult: &trustedrouter.SettleResult{CostMicrodollars: 24, Provider: "planner-provider"},
	}
}

func webSearchFinalCall(text string) fusionCallResult {
	return fusionCallResult{
		Result: adapter.StreamResult{
			Text:     text,
			Thinking: []adapter.ThinkingBlock{{Text: "checked the evidence"}},
			Usage:    &adapter.StreamUsage{InputTokens: 31, OutputTokens: 9, ReasoningTokens: 4, CacheReadInputTokens: 7},
		},
		Model:            "final/model",
		InputTokens:      31,
		OutputTokens:     9,
		SettlementResult: &trustedrouter.SettleResult{CostMicrodollars: 23, Provider: "final-provider"},
	}
}

func mustJSONString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestExecuteResponsesWebSearchRunsBoundedToolLoopAndAccountsSubcalls(t *testing.T) {
	runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{
		webSearchPlannerCall("trusted router release"),
		webSearchFinalCall("The release is live."),
	}}
	searcher := &fakeResponsesWebSearcher{results: []websearch.Result{{
		RequestID:        "exa-secret-request-id",
		CostMicrodollars: 7,
		Sources: []websearch.Source{{
			Title:   "Release notes",
			URL:     "https://example.com/release",
			Snippet: "The release is live.",
		}},
	}}}
	req := webSearchTestRequest()
	req.Models = []string{"fallback/model"}
	req.Reasoning = map[string]any{"effort": "high"}
	req.ResponseFormat = map[string]any{"type": "json_object"}

	outcome, err := executeResponsesWebSearch(context.Background(), req, runner, searcher, "root", nil)
	if err != nil {
		t.Fatalf("executeResponsesWebSearch() error = %v", err)
	}
	if runner.calls != 2 || len(searcher.queries) != 1 {
		t.Fatalf("calls = model %d search %d, want 2 and 1", runner.calls, len(searcher.queries))
	}
	if len(runner.routes) != 2 || runner.routes[0] != "responses.web_search.planner" || runner.routes[1] != "responses.web_search.final" {
		t.Fatalf("routes = %#v", runner.routes)
	}
	plannerReq := runner.requests[0]
	if plannerReq.AdditionalCostReservationMicrodollars != maxWebSearchCostPerCallMicrodollars || plannerReq.AdditionalCostMicrodollars != 7 {
		t.Fatalf("planner cost reservation/actual = %d/%d", plannerReq.AdditionalCostReservationMicrodollars, plannerReq.AdditionalCostMicrodollars)
	}
	if got := searcher.queries[0]; got != "trusted router release" {
		t.Fatalf("query = %q", got)
	}
	if got := searcher.options[0].SearchType; got != "instant" {
		t.Fatalf("search type = %q, want instant", got)
	}
	if outcome.InputTokens != 42 || outcome.OutputTokens != 12 || outcome.ModelCostMicrodollars != 40 || outcome.TotalCostMicrodollars != 47 {
		t.Fatalf("aggregated usage = %#v", outcome)
	}
	if outcome.CachedTokens != 7 || outcome.ReasoningTokens != 4 || outcome.SearchCostMicrodollars != 7 {
		t.Fatalf("extended usage = %#v", outcome)
	}
	if len(outcome.WebCalls) != 1 || !strings.HasPrefix(outcome.WebCalls[0].ID, "ws_") {
		t.Fatalf("web calls = %#v", outcome.WebCalls)
	}
	finalReq := runner.requests[1]
	if finalReq.Model != "planner/model" || len(finalReq.Models) != 2 || finalReq.Models[0] != "planner/model" {
		t.Fatalf("continuation models = model:%q models:%#v", finalReq.Model, finalReq.Models)
	}
	if finalReq.Provider == nil || len(finalReq.Provider.Order) == 0 || finalReq.Provider.Order[0] != "planner-provider" {
		t.Fatalf("continuation provider = %#v", finalReq.Provider)
	}
	if plannerReq.Reasoning != nil || plannerReq.ResponseFormat != nil || finalReq.Reasoning == nil || finalReq.ResponseFormat == nil {
		t.Fatalf("reasoning settings should be final-only: planner=%#v final=%#v", plannerReq.Reasoning, finalReq.Reasoning)
	}
	if len(finalReq.Tools) != 0 || finalReq.ToolChoice != nil {
		t.Fatalf("internal search tool leaked into final request: tools=%#v choice=%#v", finalReq.Tools, finalReq.ToolChoice)
	}
	encodedMessages, _ := json.Marshal(finalReq.Messages)
	messageText := string(encodedMessages)
	for _, expected := range []string{"UNTRUSTED WEB SEARCH DATA", "call_internal_1", "https://example.com/release"} {
		if !strings.Contains(messageText, expected) {
			t.Fatalf("final messages missing %q: %s", expected, messageText)
		}
	}
	providerUsageJSON, _ := json.Marshal(responsesWebSearchProviderUsage(outcome))
	providerUsage := responsesWebSearchProviderUsage(outcome)
	if providerUsage["total_cost_microdollars"] != 47 || providerUsage["web_search_cost_microdollars"] != 7 {
		t.Fatalf("provider usage cost = %#v", providerUsage)
	}
	if strings.Contains(string(providerUsageJSON), "trusted router release") || strings.Contains(string(providerUsageJSON), "exa-secret-request-id") {
		t.Fatalf("private search data leaked into provider usage: %s", providerUsageJSON)
	}
}

func TestExecuteResponsesWebSearchAllowsModelToAnswerWithoutSearch(t *testing.T) {
	direct := webSearchFinalCall("No search was needed.")
	direct.Result.Thinking = nil
	runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{direct}}
	searcher := &fakeResponsesWebSearcher{}

	outcome, err := executeResponsesWebSearch(context.Background(), webSearchTestRequest(), runner, searcher, "root", nil)
	if err != nil {
		t.Fatalf("executeResponsesWebSearch() error = %v", err)
	}
	if runner.calls != 1 || len(searcher.queries) != 0 || len(outcome.WebCalls) != 0 {
		t.Fatalf("unexpected calls: runner=%d search=%d outcome=%#v", runner.calls, len(searcher.queries), outcome)
	}
}

func TestExecuteResponsesWebSearchPreservesSettledPlannerMetadataOnSearchFailure(t *testing.T) {
	runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{webSearchPlannerCall("failing search")}}
	searcher := &fakeResponsesWebSearcher{errors: []error{&websearch.ProviderError{StatusCode: 429, Retryable: true}}}

	outcome, err := executeResponsesWebSearch(context.Background(), webSearchTestRequest(), runner, searcher, "root", nil)
	if err == nil {
		t.Fatal("expected search provider error")
	}
	if len(outcome.ModelCalls) != 0 {
		t.Fatalf("failed search must refund the planner instead of settling it: %#v", outcome)
	}
}

func TestExecuteResponsesWebSearchRejectsProviderCostAboveReservedBound(t *testing.T) {
	runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{webSearchPlannerCall("expensive search")}}
	searcher := &fakeResponsesWebSearcher{results: []websearch.Result{{
		CostMicrodollars: maxWebSearchCostPerCallMicrodollars + 1,
	}}}

	_, err := executeResponsesWebSearch(context.Background(), webSearchTestRequest(), runner, searcher, "root", nil)
	if err == nil || !strings.Contains(err.Error(), "cost exceeded") {
		t.Fatalf("error = %v, want bounded cost failure", err)
	}
}

func TestExecuteResponsesWebSearchRejectsInvalidPlannerCalls(t *testing.T) {
	tests := []struct {
		name string
		call types.ToolCall
	}{
		{name: "missing id", call: types.ToolCall{Name: adapter.TrustedRouterWebSearchFunction, Arguments: `{"query":"x"}`}},
		{name: "unknown argument", call: types.ToolCall{ID: "call_1", Name: adapter.TrustedRouterWebSearchFunction, Arguments: `{"query":"x","secret":true}`}},
		{name: "empty query", call: types.ToolCall{ID: "call_1", Name: adapter.TrustedRouterWebSearchFunction, Arguments: `{"query":""}`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{{Result: adapter.StreamResult{ToolCalls: []types.ToolCall{test.call}}}}}
			_, err := executeResponsesWebSearch(context.Background(), webSearchTestRequest(), runner, &fakeResponsesWebSearcher{}, "root", nil)
			if err == nil {
				t.Fatal("expected planner validation error")
			}
		})
	}
	t.Run("mixed caller and hosted calls", func(t *testing.T) {
		planner := webSearchPlannerCall("x")
		planner.Result.ToolCalls = append(planner.Result.ToolCalls, types.ToolCall{ID: "call_user", Name: "caller_function", Arguments: `{}`})
		runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{planner}}
		_, err := executeResponsesWebSearch(context.Background(), webSearchTestRequest(), runner, &fakeResponsesWebSearcher{}, "root", nil)
		if err == nil {
			t.Fatal("expected mixed-tool validation error")
		}
	})
}

func TestResponsesWebSearchPrivacyFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		model    string
		provider *types.ProviderRouting
	}{
		{name: "zdr alias", model: "trustedrouter/zdr"},
		{name: "e2e alias", model: "trustedrouter/e2e"},
		{name: "confidential alias", model: "trustedrouter/confidential"},
		{name: "eu alias", model: "trustedrouter/eu"},
		{name: "provider deny", model: "test/model", provider: &types.ProviderRouting{DataCollection: "deny"}},
		{name: "provider eu", model: "test/model", provider: &types.ProviderRouting{Jurisdiction: "eu"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := webSearchTestRequest()
			req.Model = test.model
			req.Provider = test.provider
			if err := validateResponsesWebSearchPrivacy(req); err == nil || err.Status != 400 {
				t.Fatalf("privacy error = %#v", err)
			}
		})
	}
	if err := validateResponsesWebSearchPrivacy(webSearchTestRequest()); err != nil {
		t.Fatalf("normal request rejected: %v", err)
	}
}

func TestResponsesWebSearchRejectsCustomModelWithPrivateBaseBeforeSearch(t *testing.T) {
	for _, baseModel := range []string{
		"trustedrouter/zdr",
		"trustedrouter/e2e",
		"trustedrouter/confidential",
		"trustedrouter/eu",
	} {
		t.Run(baseModel, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/gateway/resolve-custom-model" {
					t.Fatalf("path = %q", r.URL.Path)
				}
				_, _ = fmt.Fprintf(w, `{"data":{"custom_model":{"id":"trustedrouter/user-private","base_model_id":%s,"revision":1}}}`, mustJSONString(baseModel))
			}))
			defer server.Close()
			gateway := trustedrouter.New(server.URL, "internal", server.Client())
			req := webSearchTestRequest()
			req.Model = "trustedrouter/user-private"
			err := preflightResponsesWebSearchPrivacy(context.Background(), req, gateway, "sk-test")
			if err == nil {
				t.Fatal("expected private custom-model base to reject web search")
			}
		})
	}
}

func TestResponsesWebSearchStreamingUsesStableItemIDAndCompletes(t *testing.T) {
	runner := &fakeResponsesWebSearchRunner{results: []fusionCallResult{
		webSearchPlannerCall("streaming web search"),
		webSearchFinalCall("Current answer."),
	}}
	searcher := &fakeResponsesWebSearcher{results: []websearch.Result{{
		Sources: []websearch.Source{{Title: "Source", URL: "https://example.com/source", Snippet: "Evidence"}},
	}}}
	req := webSearchTestRequest()
	req.Stream = true
	var output bytes.Buffer
	emitter := newResponsesWebSearchEmitter(&output, "resp_test", req.Model, req)
	if err := emitter.Start(); err != nil {
		t.Fatal(err)
	}
	outcome, err := executeResponsesWebSearch(context.Background(), req, runner, searcher, "root", emitter)
	if err != nil {
		t.Fatal(err)
	}
	if err := emitter.Finish(outcome); err != nil {
		t.Fatal(err)
	}
	stream := output.String()
	for _, event := range []string{
		"response.created", "response.web_search_call.in_progress", "response.web_search_call.searching",
		"response.web_search_call.completed", "response.reasoning_text.delta", "response.output_text.delta",
		"response.completed", "data: [DONE]",
	} {
		if !strings.Contains(stream, event) {
			t.Fatalf("stream missing %q:\n%s", event, stream)
		}
	}
	if len(outcome.WebCalls) != 1 {
		t.Fatalf("web calls = %#v", outcome.WebCalls)
	}
	if got := strings.Count(stream, `"item_id":"`+outcome.WebCalls[0].ID+`"`); got < 3 {
		t.Fatalf("web search item id changed across events; count=%d stream=%s", got, stream)
	}
}

func TestServeOneResponsesWebSearchEndToEnd(t *testing.T) {
	previousSearcher := enclaveWebSearchClient
	enclaveWebSearchClient = &fakeResponsesWebSearcher{results: []websearch.Result{{
		CostMicrodollars: 7,
		Sources: []websearch.Source{{
			Title: "Release", URL: "https://example.com/release", Snippet: "The release is live.",
		}},
	}}}
	t.Cleanup(func() { enclaveWebSearchClient = previousSearcher })

	trGateway, recorder, closeGateway := newFusionGatewayRecorder(t)
	defer closeGateway()
	server, client := net.Pipe()
	defer client.Close()
	go serveOne(context.Background(), server, auth.New(nil), webSearchScriptedLLM{}, nil, nil, trGateway, nil)

	requestBody := []byte(`{"model":"test/model","input":"What changed?","tools":[{"type":"web_search","search_context_size":"low"}],"tool_choice":"required","include":["web_search_call.action.sources"],"store":false}`)
	if _, err := fmt.Fprintf(
		client,
		"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer test-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody), requestBody,
	); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	for _, expected := range []string{"web_search_call", "https://example.com/release", "provider_usage"} {
		if !bytes.Contains(body, []byte(expected)) {
			t.Fatalf("response missing %q: %s", expected, body)
		}
	}
	var responsePayload map[string]any
	if err := json.Unmarshal(body, &responsePayload); err != nil {
		t.Fatal(err)
	}
	usage, _ := responsePayload["usage"].(map[string]any)
	providerUsage, _ := usage["provider_usage"].(map[string]any)
	if usage["total_cost_microdollars"] != float64(9) || providerUsage["web_search_cost_microdollars"] != float64(7) {
		t.Fatalf("response usage = %#v", usage)
	}
	recorder.mu.Lock()
	authorizeCount := len(recorder.authorize)
	settleCount := len(recorder.settle)
	refundCount := len(recorder.refund)
	recorder.mu.Unlock()
	if authorizeCount != 2 || settleCount != 2 || refundCount != 0 {
		t.Fatalf("gateway calls authorize=%d settle=%d refund=%d", authorizeCount, settleCount, refundCount)
	}
	plannerAuthorize := recorder.authorize[0]
	plannerSettle := recorder.settle[0]
	if plannerAuthorize["route_type"] != "responses.web_search.planner" || plannerAuthorize["additional_cost_reservation_microdollars"] != float64(3*maxWebSearchCostPerCallMicrodollars) {
		t.Fatalf("planner authorize = %#v", plannerAuthorize)
	}
	if plannerSettle["route_type"] != "responses.web_search.planner" || plannerSettle["additional_cost_microdollars"] != float64(7) {
		t.Fatalf("planner settle = %#v", plannerSettle)
	}
}
