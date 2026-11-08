package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func namespaceTools() []any {
	var tools []any
	_ = json.Unmarshal([]byte(`[
		{"type":"function","name":"top_level","parameters":{"type":"object","properties":{}}},
		{"type":"namespace","name":"crm","description":"CRM tools.","tools":[
			{"type":"function","name":"get_customer_profile","description":"Fetch a profile.","parameters":{"type":"object","properties":{"customer_id":{"type":"string"}}}},
			{"type":"function","name":"list_open_orders","defer_loading":true,"strict":true,"parameters":{"type":"object","properties":{}}}
		]},
		{"type":"tool_search"}
	]`), &tools)
	return tools
}

func TestResponsesNamespaceToolsFlattenToFunctions(t *testing.T) {
	chat, err := ChatToolsFromResponsesTools(namespaceTools())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range chat {
		fn := tool.(map[string]any)["function"].(map[string]any)
		if _, ok := fn["defer_loading"]; ok {
			t.Fatalf("defer_loading reached the provider: %v", fn)
		}
		names = append(names, fn["name"].(string))
	}
	if got := strings.Join(names, ","); got != "top_level,get_customer_profile,list_open_orders" {
		t.Fatalf("flattened tools = %s", got)
	}
	strict := chat[2].(map[string]any)["function"].(map[string]any)["strict"]
	if strict != true {
		t.Fatalf("inner function lost strict: %v", chat[2])
	}
	descriptions := map[string]any{}
	for _, tool := range chat {
		fn := tool.(map[string]any)["function"].(map[string]any)
		descriptions[fn["name"].(string)] = fn["description"]
	}
	if got := descriptions["get_customer_profile"]; got != "Part of the crm tools: CRM tools.\n\nFetch a profile." {
		t.Fatalf("namespaced description = %q", got)
	}
	if got := descriptions["list_open_orders"]; got != "Part of the crm tools: CRM tools." {
		t.Fatalf("namespaced description without its own = %q", got)
	}
	if got, ok := descriptions["top_level"]; ok && got != nil {
		t.Fatalf("top-level description changed: %q", got)
	}
}

func TestResponsesNamespaceToolsRejections(t *testing.T) {
	for _, tc := range []struct {
		name, tools, context string
		status               int
	}{
		{"duplicate across namespaces", `[{"type":"namespace","name":"a","tools":[{"type":"function","name":"search"}]},{"type":"namespace","name":"b","tools":[{"type":"function","name":"search"}]}]`, "tools.function.name", 400},
		{"duplicate with top level", `[{"type":"function","name":"search"},{"type":"namespace","name":"b","tools":[{"type":"function","name":"search"}]}]`, "tools.function.name", 400},
		{"inner non-function", `[{"type":"namespace","name":"a","tools":[{"type":"function","name":"ok"},{"type":"web_search"}]}]`, "tools[0].tools[1].type", 501},
		{"missing name", `[{"type":"namespace","tools":[{"type":"function","name":"ok"}]}]`, "tools[0].name", 400},
		{"tools not an array", `[{"type":"namespace","name":"a","tools":{"type":"function"}}]`, "tools[0].tools", 400},
		{"client tool search", `[{"type":"function","name":"ok"},{"type":"tool_search","execution":"client"}]`, "tools[1].execution", 501},
		{"reserved inner name", `[{"type":"namespace","name":"a","tools":[{"type":"function","name":"` + TrustedRouterWebSearchFunction + `"}]}]`, "tools.function.name", 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tools []any
			if err := json.Unmarshal([]byte(tc.tools), &tools); err != nil {
				t.Fatal(err)
			}
			_, err := ChatToolsFromResponsesTools(tools)
			adapterErr, ok := err.(*AdapterError)
			if !ok || adapterErr.Status != tc.status || adapterErr.Context != tc.context {
				t.Fatalf("err = %#v, want %d %s", err, tc.status, tc.context)
			}
		})
	}
}

func TestResponsesHostedToolSearchAloneSendsNoTools(t *testing.T) {
	for _, execution := range []string{``, `,"execution":"server"`} {
		var tools []any
		_ = json.Unmarshal([]byte(`[{"type":"tool_search"`+execution+`}]`), &tools)
		chat, err := ChatToolsFromResponsesTools(tools)
		if err != nil || len(chat) != 0 {
			t.Fatalf("tool_search%s: chat=%v err=%v", execution, chat, err)
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

func TestResponsesNamespacedCallCarriesNamespace(t *testing.T) {
	meta := &types.ResponseRequestMeta{Tools: namespaceTools()}
	calls := []types.ToolCall{
		{ID: "fc_1", CallID: "call_1", Name: "list_open_orders", Arguments: `{}`},
		{ID: "fc_2", CallID: "call_2", Name: "top_level", Arguments: `{}`},
	}
	object := BuildResponsesObject("resp_ns", "m", "", calls, 1, 1, 0, 0, 1, "completed", nil, meta)
	output := object["output"].([]map[string]any)
	var namespaced, plain map[string]any
	for _, item := range output {
		switch item["name"] {
		case "list_open_orders":
			namespaced = item
		case "top_level":
			plain = item
		}
	}
	if namespaced["namespace"] != "crm" || namespaced["name"] != "list_open_orders" {
		t.Fatalf("namespaced call = %v", namespaced)
	}
	if _, ok := plain["namespace"]; ok {
		t.Fatalf("top-level call gained a namespace: %v", plain)
	}

	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"get_customer_profile","input":{}}}`, "",
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"customer_id\":\"C1\"}"}}`, "",
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`, "",
		`event: message_stop`,
		`data: {"type":"message_stop"}`, "",
	}, "\n"))
	var out bytes.Buffer
	if _, err := TransformResponsesStream(stream, &out, "resp_ns", "m", 1, nil, &types.ResponseRequestMeta{Tools: namespaceTools()}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		item, _ := event["item"].(map[string]any)
		if item["type"] == "function_call" {
			if item["namespace"] != "crm" {
				t.Fatalf("%s item lacks its namespace: %v", event["type"], item)
			}
			seen[event["type"].(string)] = true
		}
		if event["type"] == "response.completed" {
			for _, raw := range event["response"].(map[string]any)["output"].([]any) {
				item := raw.(map[string]any)
				if item["type"] == "function_call" && item["namespace"] != "crm" {
					t.Fatalf("completed output lacks the namespace: %v", item)
				}
				seen["completed"] = true
			}
		}
	}
	for _, want := range []string{"response.output_item.added", "response.output_item.done", "completed"} {
		if !seen[want] {
			t.Fatalf("no namespaced function_call in %s: %s", want, out.String())
		}
	}
}

func TestResponsesReplayedNamespacedCallMapsToItsFunction(t *testing.T) {
	var input []any
	_ = json.Unmarshal([]byte(`[
		{"role":"user","content":"orders?"},
		{"type":"function_call","name":"list_open_orders","namespace":"crm","call_id":"call_1","arguments":"{}"},
		{"type":"function_call_output","call_id":"call_1","output":"none"}
	]`), &input)
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: input, Tools: namespaceTools()})
	if err != nil {
		t.Fatal(err)
	}
	if len(chat.Messages) != 3 || len(chat.Messages[1].ToolCalls) != 1 || chat.Messages[1].ToolCalls[0].Function.Name != "list_open_orders" {
		t.Fatalf("messages = %+v", chat.Messages)
	}
	if chat.Messages[2].Role != "tool" || chat.Messages[2].ToolCallID != "call_1" {
		t.Fatalf("tool output = %+v", chat.Messages[2])
	}
}
