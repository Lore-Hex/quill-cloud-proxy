package adapter

import (
	"bytes"
	"encoding/json"
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
