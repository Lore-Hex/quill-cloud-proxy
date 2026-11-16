package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func decodeTools(t *testing.T, raw string) []any {
	t.Helper()
	var tools []any
	if err := json.Unmarshal([]byte(raw), &tools); err != nil {
		t.Fatal(err)
	}
	return tools
}

const namespaceToolsJSON = `[
	{"type":"function","name":"search","parameters":{"type":"object","properties":{}}},
	{"type":"namespace","name":"crm","description":"CRM tools.","tools":[
		{"type":"function","name":"get_customer_profile","description":"Fetch a profile.","parameters":{"type":"object","properties":{"customer_id":{"type":"string"}}}},
		{"type":"function","name":"list_open_orders","defer_loading":true,"strict":true,"parameters":{"type":"object","properties":{}}},
		{"type":"function","name":"search"}
	]},
	{"type":"namespace","name":"docs","tools":[{"type":"function","name":"search"},{"type":"function","function":{"name":"fetch"}}]},
	{"type":"tool_search"}
]`

func chatToolNames(tools []any) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, chatToolName(tool.(map[string]any)))
	}
	return names
}

func TestResponsesNamespaceToolsFlattenAndQualifyCollisions(t *testing.T) {
	chat, namespaces, err := chatToolsFromResponsesTools(decodeTools(t, namespaceToolsJSON))
	if err != nil {
		t.Fatal(err)
	}
	// A unique namespaced name is sent bare; a shared one is qualified by its
	// namespace, and the top-level function keeps its own.
	want := []string{"search", "get_customer_profile", "list_open_orders", "crm__search", "docs__search", "fetch"}
	if got := chatToolNames(chat); !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	wantMap := map[string]types.ResponseNamespacedFunction{
		"get_customer_profile": {Namespace: "crm", Name: "get_customer_profile"},
		"list_open_orders":     {Namespace: "crm", Name: "list_open_orders"},
		"crm__search":          {Namespace: "crm", Name: "search"},
		"docs__search":         {Namespace: "docs", Name: "search"},
		"fetch":                {Namespace: "docs", Name: "fetch"},
	}
	if !reflect.DeepEqual(namespaces, wantMap) {
		t.Fatalf("namespaces = %v", namespaces)
	}
	functions := map[string]map[string]any{}
	for _, tool := range chat {
		fn := tool.(map[string]any)["function"].(map[string]any)
		if _, ok := fn["defer_loading"]; ok {
			t.Fatalf("defer_loading reached the provider: %v", fn)
		}
		functions[fn["name"].(string)] = fn
	}
	if functions["list_open_orders"]["strict"] != true {
		t.Fatalf("inner function lost strict: %v", functions["list_open_orders"])
	}
	if got := functions["get_customer_profile"]["description"]; got != "Part of the crm tools: CRM tools.\n\nFetch a profile." {
		t.Fatalf("namespaced description = %q", got)
	}
	if got := functions["list_open_orders"]["description"]; got != "Part of the crm tools: CRM tools." {
		t.Fatalf("namespaced description without its own = %q", got)
	}
	if _, ok := functions["search"]["description"]; ok {
		t.Fatalf("top-level description changed: %v", functions["search"])
	}
	if _, ok := functions["docs__search"]["description"]; ok {
		t.Fatalf("namespace without a description added one: %v", functions["docs__search"])
	}
}

func TestResponsesToolsWithoutNamespacesAreUnchanged(t *testing.T) {
	// Duplicate top-level functions pass through as before; uniqueness is
	// only enforced where a namespace makes a name ambiguous.
	chat, namespaces, err := chatToolsFromResponsesTools(decodeTools(t, `[{"type":"function","name":"a"},{"type":"function","name":"a"}]`))
	if err != nil || len(chat) != 2 || namespaces != nil {
		t.Fatalf("chat=%v namespaces=%v err=%v", chat, namespaces, err)
	}
	// Two web_search tools keep their own error.
	_, err = ResponsesToChat(&types.OpenAIResponsesRequest{
		Model: "m", Input: "hi", Tools: decodeTools(t, `[{"type":"web_search"},{"type":"web_search"}]`),
	})
	adapterErr, ok := err.(*AdapterError)
	if !ok || adapterErr.Message != "only one web_search tool is allowed" || adapterErr.Context != "tools" {
		t.Fatalf("err = %#v", err)
	}
}

func TestResponsesNamespaceToolsRejections(t *testing.T) {
	for _, tc := range []struct {
		name, tools, context string
		status               int
	}{
		{"unqualifiable namespace name", `[{"type":"namespace","name":"crm.v2","tools":[{"type":"function","name":"search"}]},{"type":"function","name":"search"}]`, "tools[0].tools[0].name", 400},
		{"qualified name already taken", `[{"type":"function","name":"crm__search"},{"type":"function","name":"search"},{"type":"namespace","name":"crm","tools":[{"type":"function","name":"search"}]}]`, "tools[2].tools[0].name", 400},
		{"same name twice in one namespace", `[{"type":"namespace","name":"crm","tools":[{"type":"function","name":"search"},{"type":"function","name":"search"}]}]`, "tools[0].tools[1].name", 400},
		{"inner non-function", `[{"type":"namespace","name":"a","tools":[{"type":"function","name":"ok"},{"type":"web_search"}]}]`, "tools[0].tools[1].type", 501},
		{"missing name", `[{"type":"namespace","tools":[{"type":"function","name":"ok"}]}]`, "tools[0].name", 400},
		{"tools not an array", `[{"type":"namespace","name":"a","tools":{"type":"function"}}]`, "tools[0].tools", 400},
		{"client tool search", `[{"type":"function","name":"ok"},{"type":"tool_search","execution":"client"}]`, "tools[1].execution", 501},
		{"non-string execution", `[{"type":"function","name":"ok"},{"type":"tool_search","execution":5}]`, "tools[1].execution", 400},
		{"reserved inner name", `[{"type":"namespace","name":"a","tools":[{"type":"function","name":"` + TrustedRouterWebSearchFunction + `"}]}]`, "tools.function.name", 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ChatToolsFromResponsesTools(decodeTools(t, tc.tools))
			adapterErr, ok := err.(*AdapterError)
			if !ok || adapterErr.Status != tc.status || adapterErr.Context != tc.context {
				t.Fatalf("err = %#v, want %d %s", err, tc.status, tc.context)
			}
		})
	}
}

func TestResponsesHostedToolSearchSendsNothing(t *testing.T) {
	for _, execution := range []string{``, `,"execution":"server"`, `,"execution":null`} {
		chat, err := ChatToolsFromResponsesTools(decodeTools(t, `[{"type":"tool_search"`+execution+`}]`))
		if err != nil || len(chat) != 0 {
			t.Fatalf("tool_search%s: chat=%v err=%v", execution, chat, err)
		}
	}
	tools := decodeTools(t, `[{"type":"namespace","name":"crm","tools":[]},{"type":"tool_search"}]`)
	if _, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: "hi", Tools: tools}); err != nil {
		t.Fatalf("no forced call: %v", err)
	}
	for _, choice := range []any{"required", map[string]any{"type": "function", "name": "search"}} {
		_, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: "hi", Tools: tools, ToolChoice: choice})
		adapterErr, ok := err.(*AdapterError)
		if !ok || adapterErr.Status != 400 || adapterErr.Context != "tool_choice" {
			t.Fatalf("forced %v with nothing to call: err = %#v", choice, err)
		}
	}
}

func TestResponsesIncludeEncryptedReasoningIsAccepted(t *testing.T) {
	for _, tc := range []struct {
		include string
		status  int
	}{
		{`["reasoning.encrypted_content"]`, 0},
		{`["reasoning.encrypted_content","web_search_call.action.sources"]`, 0},
		{`["reasoning.encrypted_content","message.output_text.logprobs"]`, 501},
		{`["code_interpreter_call.outputs"]`, 501},
	} {
		err := validateResponsesInclude(json.RawMessage(tc.include))
		if tc.status == 0 {
			if err != nil {
				t.Fatalf("%s: %v", tc.include, err)
			}
			continue
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok || adapterErr.Status != tc.status || adapterErr.Context != "include" {
			t.Fatalf("%s: err = %#v", tc.include, err)
		}
	}
}

func namespaceMeta(t *testing.T) *types.ResponseRequestMeta {
	t.Helper()
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: "hi", Tools: decodeTools(t, namespaceToolsJSON)})
	if err != nil {
		t.Fatal(err)
	}
	return chat.Response
}

func TestResponsesNamespacedCallCarriesDeclaredName(t *testing.T) {
	calls := []types.ToolCall{
		{ID: "fc_1", CallID: "call_1", Name: "docs__search", Arguments: `{}`},
		{ID: "fc_2", CallID: "call_2", Name: "search", Arguments: `{}`},
		{ID: "fc_3", CallID: "call_3", Name: "fetch", Arguments: `{}`},
	}
	object := BuildResponsesObject("resp_ns", "m", "", calls, 1, 1, 0, 0, 1, "completed", nil, namespaceMeta(t))
	got := map[string][2]any{}
	for _, item := range object["output"].([]map[string]any) {
		got[item["call_id"].(string)] = [2]any{item["name"], item["namespace"]}
	}
	want := map[string][2]any{
		"call_1": {"search", "docs"},
		"call_2": {"search", nil},
		"call_3": {"fetch", "docs"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("output names = %v, want %v", got, want)
	}
}

func streamEvents(t *testing.T, body string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestResponsesStreamedNamespacedCallCarriesDeclaredName(t *testing.T) {
	start := []string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"crm__search","input":{}}}`, "",
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"q\":\"x\"}"}}`, "",
	}
	stop := []string{`event: content_block_stop`, `data: {"type":"content_block_stop","index":0}`, ""}
	end := []string{`event: message_stop`, `data: {"type":"message_stop"}`, ""}
	lines := append(append(append([]string{}, start...), stop...), end...)
	// The cap cuts the call mid-arguments, through the controlled terminal.
	capped := &StreamControl{
		BeforeSlice: func(delta StreamDelta) error {
			if delta.Type == "input_json_delta" {
				return &ControlledTermination{FinishReason: "length", TRFinishReason: "cap_reached"}
			}
			return nil
		},
		BeforeTerminal: func(terminal StreamTerminal) error { return terminal.Emit() },
	}
	for _, tc := range []struct {
		name    string
		control *StreamControl
		status  string
	}{
		{"completed call", nil, "completed"},
		{"call cut off by the cap", capped, "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := TransformResponsesStreamControlled(strings.NewReader(strings.Join(lines, "\n")), &out, "resp_ns", "m", 1, nil, namespaceMeta(t), nil, tc.control); err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, event := range streamEvents(t, out.String()) {
				eventType := event["type"].(string)
				if item, _ := event["item"].(map[string]any); item["type"] == "function_call" {
					if item["name"] != "search" || item["namespace"] != "crm" {
						t.Fatalf("%s item = %v", eventType, item)
					}
					if eventType == "response.output_item.done" && item["status"] != tc.status {
						t.Fatalf("done status = %v, want %s", item["status"], tc.status)
					}
					seen[eventType] = true
				}
				if eventType == "response.function_call_arguments.done" {
					if name, ok := event["name"]; ok && name != "search" {
						t.Fatalf("arguments.done name = %v", name)
					}
				}
				if response, _ := event["response"].(map[string]any); response != nil && (eventType == "response.completed" || eventType == "response.incomplete") {
					for _, raw := range response["output"].([]any) {
						if item := raw.(map[string]any); item["type"] == "function_call" {
							if item["name"] != "search" || item["namespace"] != "crm" {
								t.Fatalf("final output item = %v", item)
							}
							seen["final"] = true
						}
					}
				}
			}
			for _, want := range []string{"response.output_item.done", "final"} {
				if !seen[want] {
					t.Fatalf("no namespaced function_call in %s: %s", want, out.String())
				}
			}
			if !seen["response.output_item.added"] {
				t.Fatalf("no namespaced output_item.added: %s", out.String())
			}
		})
	}
}

func TestResponsesNamespacedReplayAndToolChoiceUseTheSentName(t *testing.T) {
	var input []any
	_ = json.Unmarshal([]byte(`[
		{"role":"user","content":"find it"},
		{"type":"function_call","name":"search","namespace":"crm","call_id":"call_1","arguments":"{}"},
		{"type":"function_call","name":"search","call_id":"call_2","arguments":"{}"},
		{"type":"function_call","name":"fetch","namespace":"docs","call_id":"call_3","arguments":"{}"},
		{"type":"function_call_output","call_id":"call_1","output":"none"}
	]`), &input)
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{
		Model: "m", Input: input, Tools: decodeTools(t, namespaceToolsJSON),
		ToolChoice: map[string]any{"type": "function", "name": "search", "namespace": "docs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, call := range chat.Messages[1].ToolCalls {
		names = append(names, call.Function.Name)
	}
	if want := []string{"crm__search", "search", "fetch"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("replayed names = %v, want %v", names, want)
	}
	if chat.Messages[2].Role != "tool" || chat.Messages[2].ToolCallID != "call_1" {
		t.Fatalf("tool output = %+v", chat.Messages[2])
	}
	want := map[string]any{"type": "function", "function": map[string]any{"name": "docs__search"}}
	if !reflect.DeepEqual(chat.ToolChoice, want) {
		t.Fatalf("tool_choice = %v", chat.ToolChoice)
	}
}

func TestResponsesUndeclaredNamespaceToolChoiceIsRejected(t *testing.T) {
	tools := decodeTools(t, namespaceToolsJSON)
	for _, tc := range []struct {
		name   string
		choice any
	}{
		{"tool_choice", map[string]any{"type": "function", "name": "search", "namespace": "billing"}},
		{"tool_choice with a name the namespace lacks", map[string]any{"type": "function", "name": "fetch", "namespace": "crm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A replayed call to the same function does not make it callable.
			choice := tc.choice.(map[string]any)
			replay := []any{
				map[string]any{"role": "user", "content": "find it"},
				map[string]any{"type": "function_call", "name": choice["name"], "namespace": choice["namespace"], "call_id": "call_1", "arguments": "{}"},
			}
			for _, input := range []any{"hi", replay} {
				_, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: input, Tools: tools, ToolChoice: tc.choice})
				adapterErr, ok := err.(*AdapterError)
				if !ok || adapterErr.Status != 400 || adapterErr.Context != "tool_choice.namespace" {
					t.Fatalf("err = %#v", err)
				}
			}
		})
	}
	// A namespace is matched as declared, surrounding space trimmed alike.
	spaced := decodeTools(t, `[{"type":"function","name":"search"},{"type":"namespace","name":" crm ","tools":[{"type":"function","name":"search"}]}]`)
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{
		Model: "m", Input: "hi", Tools: spaced,
		ToolChoice: map[string]any{"type": "function", "name": "search", "namespace": " crm "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := (map[string]any{"type": "function", "function": map[string]any{"name": "crm__search"}}); !reflect.DeepEqual(chat.ToolChoice, want) {
		t.Fatalf("tool_choice = %v", chat.ToolChoice)
	}
}

func TestResponsesReplayedToolSearchItems(t *testing.T) {
	tools := decodeTools(t, namespaceToolsJSON)
	hosted := []any{
		map[string]any{"role": "user", "content": "orders?"},
		map[string]any{"type": "tool_search_call", "execution": "server", "call_id": nil, "status": "completed", "arguments": map[string]any{"paths": []any{"crm"}}},
		map[string]any{"type": "tool_search_output", "execution": "server", "call_id": nil, "status": "completed", "tools": []any{}},
		map[string]any{"type": "function_call", "name": "list_open_orders", "namespace": "crm", "call_id": "call_1", "arguments": "{}"},
	}
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: hosted, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	if len(chat.Messages) != 2 || chat.Messages[1].ToolCalls[0].Function.Name != "list_open_orders" {
		t.Fatalf("messages = %+v", chat.Messages)
	}
	client := []any{
		map[string]any{"role": "user", "content": "orders?"},
		map[string]any{"type": "tool_search_output", "execution": "client", "call_id": "call_s", "status": "completed", "tools": []any{}},
	}
	_, err = ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: client, Tools: tools})
	adapterErr, ok := err.(*AdapterError)
	if !ok || adapterErr.Status != 501 || adapterErr.Context != "input[1].tool_search_output" {
		t.Fatalf("client tool search replay: err = %#v", err)
	}
}

func TestResponsesNonForcingToolChoiceDroppedWithNoTools(t *testing.T) {
	for _, choice := range []any{"auto", "none"} {
		chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{
			Model: "m", Input: "hi", Tools: decodeTools(t, `[{"type":"tool_search"}]`), ToolChoice: choice,
		})
		if err != nil {
			t.Fatal(err)
		}
		if chat.ToolChoice != nil || len(chat.Tools) != 0 {
			t.Fatalf("%v: tool_choice=%v tools=%v", choice, chat.ToolChoice, chat.Tools)
		}
	}
}

func decodeInput(t *testing.T, raw string) []any {
	t.Helper()
	var input []any
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatal(err)
	}
	return input
}

func replayedCallNames(chat *types.OpenAIChatRequest) []string {
	var names []string
	for _, message := range chat.Messages {
		for _, call := range message.ToolCalls {
			names = append(names, call.Function.Name)
		}
	}
	return names
}

// answeredAs is the name and namespace each called provider-facing name is
// answered with, read from the response the caller receives.
func answeredAs(meta *types.ResponseRequestMeta, called ...string) [][2]any {
	calls := make([]types.ToolCall, 0, len(called))
	for index, name := range called {
		calls = append(calls, types.ToolCall{ID: fmt.Sprintf("fc_%d", index), CallID: fmt.Sprintf("call_%d", index), Name: name, Arguments: `{}`})
	}
	object := BuildResponsesObject("resp_ns", "m", "", calls, 1, 1, 0, 0, 1, "completed", nil, meta)
	var out [][2]any
	for _, item := range object["output"].([]map[string]any) {
		out = append(out, [2]any{item["name"], item["namespace"]})
	}
	return out
}

func TestResponsesNamespacedCallRoundTrip(t *testing.T) {
	tools := decodeTools(t, namespaceToolsJSON)
	first, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: "find it", Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	// The model calls the names it was sent. The caller receives the declared
	// name and namespace, and replays those items with the tool outputs.
	calls := []types.ToolCall{
		{ID: "fc_1", CallID: "call_1", Name: "crm__search", Arguments: `{}`},
		{ID: "fc_2", CallID: "call_2", Name: "fetch", Arguments: `{}`},
		{ID: "fc_3", CallID: "call_3", Name: "search", Arguments: `{}`},
	}
	object := BuildResponsesObject("resp_ns", "m", "", calls, 1, 1, 0, 0, 1, "completed", nil, first.Response)
	encoded, err := json.Marshal(object["output"])
	if err != nil {
		t.Fatal(err)
	}
	input := append([]any{map[string]any{"role": "user", "content": "find it"}}, decodeInput(t, string(encoded))...)
	if got := input[1].(map[string]any); got["name"] != "search" || got["namespace"] != "crm" {
		t.Fatalf("answered call = %v", got)
	}
	for _, id := range []string{"call_1", "call_2", "call_3"} {
		input = append(input, map[string]any{"type": "function_call_output", "call_id": id, "output": "none"})
	}
	second, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: input, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := replayedCallNames(second), []string{"crm__search", "fetch", "search"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed names = %v, want %v", got, want)
	}
	for index, id := range []string{"call_1", "call_2", "call_3"} {
		if output := second.Messages[2+index]; output.Role != "tool" || output.ToolCallID != id {
			t.Fatalf("tool output %d = %+v", index, output)
		}
	}
	// A replay of declared functions adds no name of its own.
	if !reflect.DeepEqual(second.Response.FunctionNamespaces, first.Response.FunctionNamespaces) {
		t.Fatalf("namespaces = %v", second.Response.FunctionNamespaces)
	}
}

func TestResponsesUndeclaredNamespacedReplayIsHistory(t *testing.T) {
	tools := decodeTools(t, namespaceToolsJSON)
	declared, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: "hi", Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Tools: tools, Input: decodeInput(t, `[
		{"role":"user","content":"find it"},
		{"type":"function_call","name":"search","namespace":"billing","call_id":"call_1","arguments":"{}"},
		{"type":"function_call","name":"get_customer_profile","namespace":"billing","call_id":"call_2","arguments":"{}"},
		{"type":"function_call","name":"search","namespace":" billing ","call_id":"call_3","arguments":"{}"},
		{"type":"function_call","name":"search","namespace":"crm","call_id":"call_4","arguments":"{}"},
		{"type":"function_call","name":"retired","call_id":"call_5","arguments":"{}"},
		{"type":"function_call_output","call_id":"call_1","output":"none"},
		{"type":"function_call_output","call_id":"call_2","output":"none"}
	]`)})
	if err != nil {
		t.Fatal(err)
	}
	// The undeclared calls keep their namespace in the name the model reads.
	// The declared and the un-namespaced ones are sent as before.
	want := []string{"billing__search", "billing__get_customer_profile", "billing__search", "crm__search", "retired"}
	if got := replayedCallNames(chat); !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed names = %v, want %v", got, want)
	}
	for index, id := range []string{"call_1", "call_2"} {
		if output := chat.Messages[2+index]; output.Role != "tool" || output.ToolCallID != id || output.Content != "none" {
			t.Fatalf("tool output %d = %+v", index, output)
		}
	}
	// History declares nothing: the model is offered the same functions.
	if !reflect.DeepEqual(chatToolNames(chat.Tools), chatToolNames(declared.Tools)) {
		t.Fatalf("tools = %v", chatToolNames(chat.Tools))
	}
	// A later call to a declared function is answered as declared, whatever
	// history shares its name. A call to a history-only function is answered
	// with the namespace and name the caller replayed.
	got := answeredAs(chat.Response, "search", "crm__search", "docs__search", "get_customer_profile", "fetch", "billing__search", "billing__get_customer_profile", "retired")
	wantAnswers := [][2]any{
		{"search", nil}, {"search", "crm"}, {"search", "docs"}, {"get_customer_profile", "crm"}, {"fetch", "docs"},
		{"search", "billing"}, {"get_customer_profile", "billing"}, {"retired", nil},
	}
	if !reflect.DeepEqual(got, wantAnswers) {
		t.Fatalf("answers = %v, want %v", got, wantAnswers)
	}
	if before := answeredAs(declared.Response, "search", "crm__search", "docs__search", "get_customer_profile", "fetch"); !reflect.DeepEqual(before, wantAnswers[:5]) {
		t.Fatalf("declared answers changed: %v", before)
	}
}

func TestResponsesUndeclaredNamespacedReplayNames(t *testing.T) {
	long := strings.Repeat("n", 40)
	for _, tc := range []struct {
		name, tools, namespace, function, want string
	}{
		{"no tools", ``, "billing", "search", "billing__search"},
		{"history from another backend", `[{"type":"function","name":"search"}]`, "billing", "search", "billing__search"},
		{"bare name declared in another namespace", `[{"type":"namespace","name":"crm","tools":[{"type":"function","name":"search"}]}]`, "billing", "search", "billing__search"},
		{"qualified name is a top-level function", `[{"type":"function","name":"billing__search"}]`, "billing", "search", "billing__search_c69c1805"},
		{"qualified name is a namespaced function", `[{"type":"namespace","name":"crm","tools":[{"type":"function","name":"billing__search"}]}]`, "billing", "search", "billing__search_c69c1805"},
		{"qualified name is another qualified function", `[{"type":"function","name":"c"},{"type":"namespace","name":"a__b","tools":[{"type":"function","name":"c"}]}]`, "a", "b__c", "a__b__c_"},
		{"beside the hosted search function", `[{"type":"web_search"}]`, "_trustedrouter_web", "search", "_trustedrouter_web__search"},
		{"not a function name", ``, "crm.v2", "search/all", "crm_v2__search_all_"},
		{"not ascii", ``, "crm", "suche\u00fc", "crm__suche__"},
		{"over 64 characters", ``, long, long, long + "__" + long[:13] + "_"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tools []any
			if tc.tools != "" {
				tools = decodeTools(t, tc.tools)
			}
			convert := func() (*types.OpenAIChatRequest, string) {
				chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Tools: tools, Input: decodeInput(t, `[
					{"role":"user","content":"find it"},
					{"type":"function_call","name":"`+tc.function+`","namespace":"`+tc.namespace+`","call_id":"call_1","arguments":"{}"},
					{"type":"function_call_output","call_id":"call_1","output":"none"}
				]`)})
				if err != nil {
					t.Fatal(err)
				}
				return chat, chat.Messages[1].ToolCalls[0].Function.Name
			}
			chat, sent := convert()
			if !providerFunctionName.MatchString(sent) {
				t.Fatalf("sent %q is not a name providers accept", sent)
			}
			if strings.HasSuffix(tc.want, "_") {
				// A readable prefix, then eight hexadecimal digits of the digest.
				if !strings.HasPrefix(sent, tc.want) || len(sent) != len(tc.want)+8 {
					t.Fatalf("sent %q, want %s and a digest", sent, tc.want)
				}
			} else if sent != tc.want {
				t.Fatalf("sent %q, want %q", sent, tc.want)
			}
			if _, again := convert(); again != sent {
				t.Fatalf("name is not deterministic: %q then %q", sent, again)
			}
			for _, name := range chatToolNames(chat.Tools) {
				if name == sent {
					t.Fatalf("history took the name of declared function %q", name)
				}
			}
			var function map[string]any
			if err := json.Unmarshal([]byte(`{"name":"`+tc.function+`"}`), &function); err != nil {
				t.Fatal(err)
			}
			if got := answeredAs(chat.Response, sent); !reflect.DeepEqual(got, [][2]any{{function["name"], tc.namespace}}) {
				t.Fatalf("a call to %q is answered as %v", sent, got)
			}
		})
	}
}

func TestResponsesUndeclaredNamespacedReplayKeepsHistoryApart(t *testing.T) {
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: decodeInput(t, `[
		{"role":"user","content":"find it"},
		{"type":"function_call","name":"search","namespace":"crm.v2","call_id":"call_1","arguments":"{}"},
		{"type":"function_call","name":"search","namespace":"crm/v2","call_id":"call_2","arguments":"{}"},
		{"type":"function_call","name":"b__c","namespace":"a","call_id":"call_3","arguments":"{}"},
		{"type":"function_call","name":"c","namespace":"a__b","call_id":"call_4","arguments":"{}"},
		{"type":"function_call","name":"search","namespace":"billing","call_id":"call_5","arguments":"{}"},
		{"type":"function_call","name":"billing__search","call_id":"call_6","arguments":"{}"},
		{"type":"custom_tool_call","name":"billing__patch","call_id":"call_7","input":"x"},
		{"type":"function_call","name":"patch","namespace":"billing","call_id":"call_8","arguments":"{}"}
	]`)})
	if err != nil {
		t.Fatal(err)
	}
	names := replayedCallNames(chat)
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("two functions share the name %q: %v", name, names)
		}
		seen[name] = true
	}
	if names[2] != "a__b__c" || names[5] != "billing__search" || names[6] != "billing__patch" {
		t.Fatalf("names = %v", names)
	}
	// The un-namespaced calls keep their names, so a call to one is answered
	// without the namespace of the function that would have shared it.
	want := [][2]any{{"b__c", "a"}, {"c", "a__b"}, {"search", "billing"}, {"billing__search", nil}, {"billing__patch", nil}, {"patch", "billing"}}
	if got := answeredAs(chat.Response, names[2:]...); !reflect.DeepEqual(got, want) {
		t.Fatalf("answers = %v, want %v", got, want)
	}
}

func TestResponsesMalformedNamespacedReplayIsRejected(t *testing.T) {
	for _, tc := range []struct{ item, context string }{
		{`{"type":"function_call","namespace":"billing","call_id":"call_1","arguments":"{}"}`, "input[1].name"},
		{`{"type":"function_call","namespace":"billing","name":" ","call_id":"call_1","arguments":"{}"}`, "input[1].name"},
		{`{"type":"function_call","namespace":"billing","name":"search","arguments":"{}"}`, "input[1].call_id"},
		{`{"type":"function_call","namespace":"billing","name":"search","call_id":"call_1","arguments":{"q":"x"}}`, "input[1].arguments"},
		{`{"type":"function_call","namespace":"billing","name":"search","call_id":"call_1","arguments":"{"}`, "input[1].arguments"},
	} {
		for _, tools := range []string{`[]`, namespaceToolsJSON} {
			_, err := ResponsesToChat(&types.OpenAIResponsesRequest{
				Model: "m", Tools: decodeTools(t, tools), Input: decodeInput(t, `[{"role":"user","content":"find it"},`+tc.item+`]`),
			})
			adapterErr, ok := err.(*AdapterError)
			if !ok || adapterErr.Status != 400 || adapterErr.Context != tc.context {
				t.Fatalf("%s: err = %#v, want 400 %s", tc.item, err, tc.context)
			}
		}
	}
}
