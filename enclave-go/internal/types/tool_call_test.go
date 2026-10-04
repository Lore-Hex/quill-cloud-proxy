package types

import (
	"encoding/json"
	"testing"
)

func TestOpenAIToolCallNameRecovery(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"ignored custom string", `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"},"custom":"x"}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}`},
		{"ignored custom non-string name", `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"},"custom":{"name":5}}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}`},
		{"ignored custom array", `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"},"custom":[]}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}`},
		{"ignored out of range name", `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"},"name":1e999}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}`},
		{"ignored out of range arguments", `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"},"arguments":1e999}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}`},
		{"custom type with function", `{"id":"c","type":"custom","function":{"name":"f","arguments":"{\"a\":1}"}}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}`},
		{"custom type with top level", `{"id":"c","type":"custom","name":"f","arguments":"{\"a\":1}"}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}`},
		{"custom with empty function", `{"id":"c","custom":{"name":"f","input":"x"},"function":{}}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{\"input\":\"x\"}"}}`},
		{"null nested arguments fallback", `{"id":"c","type":"function","function":{"name":"f","arguments":null},"arguments":"{\"a\":1}"}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}`},
		{"whitespace name top level fallback", `{"id":"c","type":"function","function":{"name":" \t","arguments":"{}"},"name":"f"}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}`},
		{"whitespace name custom fallback", `{"id":"c","custom":{"name":"f","input":"x"},"function":{"name":" \t"}}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{\"input\":\"x\"}"}}`},
		{"whitespace custom name top level fallback", `{"id":"c","type":"custom","custom":{"name":" \t","input":"x"},"name":"f"}`, `{"id":"c","type":"function","function":{"name":"f","arguments":"{\"input\":\"x\"}"}}`},
		{"whitespace without usable fallback preserved", `{"id":"c","type":"custom","function":{"name":" \t","arguments":"{}"},"custom":{"name":" "},"name":" "}`, `{"id":"c","type":"custom","function":{"name":" \t","arguments":"{}"}}`},
		{"custom string", `{"id":"call_1","type":"custom","custom":{"name":"get_weather","input":"Paris"}}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"input\":\"Paris\"}"}}`},
		{"custom object without type", `{"id":"call_1","custom":{"name":"get_weather","input":{"city":"Paris"}}}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"input\":{\"city\":\"Paris\"}}"}}`},
		{"custom array", `{"id":"call_1","type":"custom","custom":{"name":"get_weather","input":[1,true,null]}}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"input\":[1,true,null]}"}}`},
		{"custom null", `{"id":"call_1","type":"custom","custom":{"name":"get_weather","input":null}}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"input\":null}"}}`},
		{"top level", `{"id":"call_1","type":"function","name":"get_weather","arguments":"{\"city\":\"Paris\"}"}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}`},
		{"null with top level", `{"id":"call_1","type":"function","function":{"name":null},"name":"get_weather","arguments":"{}"}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{}"}}`},
		{"standard", `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}`},
		{"nested wins", `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{}"},"name":"wrong","arguments":"wrong","custom":{"name":"wrong","input":"wrong"}}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{}"}}`},
		{"empty nested arguments wins", `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""},"arguments":"wrong"}`, `{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}`},
		{"no type", `{"id":"call_1","function":{"name":"get_weather","arguments":"{}"}}`, `{"id":"call_1","function":{"name":"get_weather","arguments":"{}"}}`},
		{"null name", `{"id":"call_1","type":"function","function":{"name":null,"arguments":"{}"}}`, `{"id":"call_1","type":"function","function":{"name":"","arguments":"{}"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var call, want OpenAIToolCall
			if err := json.Unmarshal([]byte(tc.input), &call); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if call != want {
				t.Errorf("decoded = %#v, want %#v", call, want)
			}
			encoded, err := json.Marshal(call)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tc.want {
				t.Errorf("marshal = %s, want %s", encoded, tc.want)
			}
		})
	}
	// Compatibility checks: non-string nested arguments must still fail, even
	// when a recoverable top-level name or arguments value is present.
	for _, arguments := range []string{`{}`, `[]`, `42`, `true`} {
		var call OpenAIToolCall
		if err := json.Unmarshal([]byte(`{"name":"get_weather","arguments":"{}","function":{"arguments":`+arguments+`}}`), &call); err == nil {
			t.Errorf("accepted nested arguments %s", arguments)
		}
	}
}

func TestRecoverToolCallNames(t *testing.T) {
	var messages []OpenAIChatMessage
	if err := json.Unmarshal([]byte(`[
  {"role":"assistant","tool_calls":[
   {"id":"match","type":"function","function":{"name":null,"arguments":"{}"}},
   {"id":"missing","type":"function","function":{"name":null,"arguments":"{}"}},
   {"id":"unnamed","type":"function","function":{"name":null,"arguments":"{}"}},
   {"id":"named","type":"function","function":{"name":"keep_me","arguments":"{}"}}]},
  {"role":"tool","tool_call_id":"unrelated","name":"wrong","content":"result"},
  {"role":"tool","tool_call_id":"match","name":"get_weather","content":"result"},
  {"role":"tool","tool_call_id":"unnamed","content":"result"},
  {"role":"tool","tool_call_id":"named","name":"wrong","content":"result"},
  {"role":"user","tool_call_id":"missing","name":"wrong","content":"hello"},
  {"role":"user","tool_calls":[{"id":"match","function":{"name":"","arguments":"{}"}}]}
 ]`), &messages); err != nil {
		t.Fatal(err)
	}
	before := append([]OpenAIToolCall(nil), messages[0].ToolCalls...)
	RecoverToolCallNames(messages)
	before[0].Function.Name = "get_weather"
	for i, want := range before {
		if got := messages[0].ToolCalls[i]; got != want {
			t.Errorf("call %d = %#v, want %#v", i, got, want)
		}
	}
	if messages[6].ToolCalls[0].Function.Name != "" {
		t.Error("changed non-assistant call")
	}
}

func TestRecoverToolCallNamesProximity(t *testing.T) {
	var messages []OpenAIChatMessage
	if err := json.Unmarshal([]byte(`[
		{"role":"assistant","tool_calls":[{"id":"call_0","function":{"name":null}}]},
		{"role":"tool","tool_call_id":"call_0","name":"first_tool"},
		{"role":"assistant","tool_calls":[{"id":"call_0","function":{"name":null}}]},
		{"role":"tool","tool_call_id":"call_0","name":"second_tool"},
		{"role":"assistant","tool_calls":[{"id":"later","function":{"name":null}}]},
		{"role":"user","content":"interrupt"},
		{"role":"tool","tool_call_id":"later","name":"too_late"}
	]`), &messages); err != nil {
		t.Fatal(err)
	}
	RecoverToolCallNames(messages)
	for i, want := range []string{"first_tool", "second_tool", ""} {
		if got := messages[2*i].ToolCalls[0].Function.Name; got != want {
			t.Errorf("assistant %d name = %q, want %q", i, got, want)
		}
	}
}

func TestRecoverToolCallNamesWhitespace(t *testing.T) {
	var messages []OpenAIChatMessage
	if err := json.Unmarshal([]byte(`[
		{"role":"assistant","tool_calls":[
			{"id":"recover","function":{"name":" \t"}},
			{"id":"blank_result","function":{"name":null}},
			{"id":"unmatched","function":{"name":" \t"}},
			{"id":"blank_both","function":{"name":" \t"}}]},
		{"role":"tool","tool_call_id":"recover","name":"f"},
		{"role":"tool","tool_call_id":"blank_result","name":" \t"},
		{"role":"tool","tool_call_id":"blank_both","name":" "}
	]`), &messages); err != nil {
		t.Fatal(err)
	}
	RecoverToolCallNames(messages)
	for i, want := range []string{"f", "", " \t", " \t"} {
		if got := messages[0].ToolCalls[i].Function.Name; got != want {
			t.Errorf("call %d name = %q, want %q", i, got, want)
		}
	}
}
