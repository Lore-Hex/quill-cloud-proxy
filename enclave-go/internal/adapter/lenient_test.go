package adapter

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func validateChatBody(body []byte) (ChatRequestValidation, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return ChatRequestValidation{}, err
	}
	return ValidateChatRequestFields(raw)
}

func TestLenientParseDropsUnknownAndUnsupportedChatFields(t *testing.T) {
	body := []byte(`{
		"model": "m", "messages": [{"role": "user", "content": "hi"}],
		"temperature": 0.2,
		"extra_body": {"x": 1}, "safety_settings": [{"category": "c"}],
		"transforms": ["middle-out"], "think": true, "return_citations": true,
		"route": "fallback", "image_config": {"aspect_ratio": "1:1"},
		"prompt_cache_retention": "24h", "store": true, "modalities": ["text", "audio"],
		"stream_options": {"include_usage": true, "chunk": 1},
		"plugins": [{"id": "web"}, {"id": "response-healing"}, {"id": "made-up"}],
		"provider": {"order": ["a"], "quantizations": ["fp8"], "nonsense": 1,
			"max_price": {"prompt": 1, "audio": 2, "video": 3}}
	}`)
	validation, dropped, _, err := LenientParse(body, true, validateChatBody)
	if err != nil {
		t.Fatalf("lenient parse failed: %v", err)
	}
	sort.Strings(dropped)
	want := []string{
		"extra_body", "image_config", "modalities", "plugins.made-up", "plugins.response-healing",
		"prompt_cache_retention", "provider.max_price.audio", "provider.max_price.video",
		"provider.nonsense", "provider.quantizations", "return_citations", "route",
		"safety_settings", "store", "stream_options.chunk", "think", "transforms",
	}
	if !reflect.DeepEqual(dropped, want) {
		t.Fatalf("dropped = %v\nwant      %v", dropped, want)
	}
	if !reflect.DeepEqual(validation.RequestedParameters, []string{"temperature"}) {
		t.Fatalf("requested parameters = %v", validation.RequestedParameters)
	}
}

func TestLenientParseIsOffByDefault(t *testing.T) {
	body := []byte(`{"model": "m", "messages": [], "extra_body": {}}`)
	_, dropped, _, err := LenientParse(body, false, validateChatBody)
	if err == nil || dropped != nil {
		t.Fatalf("strict parse accepted an unknown field: dropped=%v err=%v", dropped, err)
	}
	if path, ok := LenientDropPath(err); !ok || path != "extra_body" {
		t.Fatalf("drop path = %q %v", path, ok)
	}
}

func TestLenientParseKeepsValueErrors(t *testing.T) {
	cases := map[string]string{
		"malformed supported field": `{"model": "m", "messages": [], "extra": 1, "store": "yes"}`,
		"malformed stream option":   `{"model": "m", "messages": [], "stream_options": {"include_usage": "yes"}}`,
		"provider not an object":    `{"model": "m", "messages": [], "provider": 3}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, dropped, _, err := LenientParse([]byte(body), true, validateChatBody)
			if err == nil {
				t.Fatalf("value error was dropped: %v", dropped)
			}
			if _, ok := LenientDropPath(err); ok {
				t.Fatalf("value error classified as droppable: %v", err)
			}
		})
	}
}

func TestLenientDropPathNeverTouchesConversation(t *testing.T) {
	for _, path := range []string{"messages[0].content[1]", "input[2].content[0].type", "input", "prompt", `message[0].role="tool"`, "previous_response_id", "conversation"} {
		if _, ok := LenientDropPath(&AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: path}); ok {
			t.Fatalf("content path %q classified as droppable", path)
		}
	}
	if path, ok := LenientDropPath(&AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "background=true"}); !ok || path != "background" {
		t.Fatalf("value-naming context resolved to %q %v", path, ok)
	}
	if _, ok := LenientDropPath(&AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "/v1/conversations"}); ok {
		t.Fatal("route error classified as droppable")
	}
}

func TestDropRequestPathShapes(t *testing.T) {
	raw := map[string]json.RawMessage{
		"tools":              json.RawMessage(`[{"type": "function", "function": {"name": "f"}}, {"type": "computer"}]`),
		"plugins":            json.RawMessage(`[{"id": "Web-Fetch"}, {"id": "web"}]`),
		"web_search_options": json.RawMessage(`{"user_location": {"city": "x"}, "search_context_size": "low"}`),
	}
	for _, path := range []string{"tools[1].type", "plugins.web-fetch", "web_search_options.user_location"} {
		if !DropRequestPath(raw, path) {
			t.Fatalf("path %q was not dropped", path)
		}
	}
	if got := string(raw["tools"]); got != `[{"type":"function","function":{"name":"f"}}]` {
		t.Fatalf("tools = %s", got)
	}
	if got := string(raw["plugins"]); got != `[{"id":"web"}]` {
		t.Fatalf("plugins = %s", got)
	}
	if got := string(raw["web_search_options"]); got != `{"search_context_size":"low"}` {
		t.Fatalf("web_search_options = %s", got)
	}
	for _, path := range []string{"missing", "tools[9]", "plugins.none", "web_search_options.none.deeper"} {
		if DropRequestPath(raw, path) {
			t.Fatalf("absent path %q reported as dropped", path)
		}
	}
}

func TestLenientParseStopsAtDropLimit(t *testing.T) {
	raw := map[string]any{"model": "m", "messages": []any{}}
	for i := 0; i < MaxLenientDrops+1; i++ {
		raw["unknown_"+string(rune('a'+i%26))+string(rune('a'+i/26))] = 1
	}
	body, _ := json.Marshal(raw)
	if _, dropped, _, err := LenientParse(body, true, validateChatBody); err == nil {
		t.Fatalf("parse past the drop limit succeeded after %d drops", len(dropped))
	}
}

func TestDropRequestPathNestedArrayContexts(t *testing.T) {
	raw := map[string]json.RawMessage{
		"plugins": json.RawMessage(`[{"id": "web", "engine": "native", "max_results": 3}]`),
		"tools":   json.RawMessage(`[{"type": "function", "function": {"name": "f", "parameters": {}}}, {"type": "openrouter:web_search", "parameters": {"engine": "native", "max_results": 2}, "extra": 1}]`),
	}
	for _, path := range []string{"plugins.web.engine", "tools.parameters.engine", "tools.extra"} {
		if !DropRequestPath(raw, path) {
			t.Fatalf("path %q was not dropped", path)
		}
	}
	if got := string(raw["plugins"]); got != `[{"id":"web","max_results":3}]` {
		t.Fatalf("plugins = %s", got)
	}
	if got := string(raw["tools"]); got != `[{"function":{"name":"f","parameters":{}},"type":"function"},{"parameters":{"max_results":2},"type":"openrouter:web_search"}]` {
		t.Fatalf("tools = %s", got)
	}
}

func TestDropRequestPathLiteralKeys(t *testing.T) {
	raw := map[string]json.RawMessage{
		"vendor.option": json.RawMessage(`1`),
		"odd[0]":        json.RawMessage(`2`),
		"provider":      json.RawMessage(`{"x.y": 3, "order": ["a"]}`),
	}
	for _, path := range []string{"vendor.option", "odd[0]", "provider.x.y"} {
		if !DropRequestPath(raw, path) {
			t.Fatalf("literal key %q was not dropped", path)
		}
	}
	if len(raw) != 1 || string(raw["provider"]) != `{"order":["a"]}` {
		t.Fatalf("raw = %v", raw)
	}
}

func TestLenientParseReturnsTheBodyThatParsed(t *testing.T) {
	body := []byte(`{"model": "m", "messages": [], "extra_body": {}}`)
	_, _, parsedBody, err := LenientParse(body, true, validateChatBody)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(parsedBody, &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["extra_body"]; present {
		t.Fatal("returned body still holds the dropped field")
	}
	if _, present := raw["model"]; !present {
		t.Fatal("returned body lost a kept field")
	}
}

func TestDropRequestPathRefusesAnAmbiguousArrayElement(t *testing.T) {
	raw := map[string]json.RawMessage{
		"tools": json.RawMessage(`[{"type": "function", "name": "f", "parameters": {"type": "object"}}, {"type": "web_search", "parameters": {"x": 1}}]`),
	}
	if DropRequestPath(raw, "tools.parameters") {
		t.Fatal("a path held by two elements was dropped from them")
	}
	if got := string(raw["tools"]); got != `[{"type": "function", "name": "f", "parameters": {"type": "object"}}, {"type": "web_search", "parameters": {"x": 1}}]` {
		t.Fatalf("tools changed: %s", got)
	}
}

func TestLenientParseReportsOriginalArrayIndexes(t *testing.T) {
	body := []byte(`{"tools": [{"type": "computer"}, {"type": "function"}, {"type": "file_search"}]}`)
	parse := func(candidate []byte) (int, error) {
		var raw struct {
			Tools []map[string]string `json:"tools"`
		}
		if err := json.Unmarshal(candidate, &raw); err != nil {
			return 0, err
		}
		for index, tool := range raw.Tools {
			if tool["type"] != "function" {
				return 0, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools[" + string(rune('0'+index)) + "].type"}
			}
		}
		return len(raw.Tools), nil
	}
	kept, dropped, _, err := LenientParse(body, true, parse)
	if err != nil || kept != 1 {
		t.Fatalf("kept=%d err=%v", kept, err)
	}
	if !reflect.DeepEqual(dropped, []string{"tools[0].type", "tools[2].type"}) {
		t.Fatalf("dropped = %v", dropped)
	}
}

func TestLenientParseReportsOriginalNestedArrayIndexes(t *testing.T) {
	body := []byte(`{"tools": [{"type": "namespace", "tools": [{"type": "custom"}, {"type": "function"}, {"type": "computer"}]}]}`)
	parse := func(candidate []byte) (int, error) {
		var raw struct {
			Tools []struct {
				Tools []map[string]string `json:"tools"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(candidate, &raw); err != nil {
			return 0, err
		}
		for index, tool := range raw.Tools[0].Tools {
			if tool["type"] != "function" {
				return 0, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools[0].tools[" + string(rune('0'+index)) + "].type"}
			}
		}
		return len(raw.Tools[0].Tools), nil
	}
	kept, dropped, _, err := LenientParse(body, true, parse)
	if err != nil || kept != 1 {
		t.Fatalf("kept=%d err=%v", kept, err)
	}
	if !reflect.DeepEqual(dropped, []string{"tools[0].tools[0].type", "tools[0].tools[2].type"}) {
		t.Fatalf("dropped = %v", dropped)
	}
}

func TestDropRequestPathMatchesDottedPluginIDs(t *testing.T) {
	raw := map[string]json.RawMessage{"plugins": json.RawMessage(`[{"id": "vendor.search", "x": 1}, {"id": "web"}]`)}
	if !DropRequestPath(raw, "plugins.vendor.search") {
		t.Fatal("dotted plugin id was not dropped")
	}
	if got := string(raw["plugins"]); got != `[{"id":"web"}]` {
		t.Fatalf("plugins = %s", got)
	}
	raw = map[string]json.RawMessage{"plugins": json.RawMessage(`[{"id": "vendor.search", "engine": "x"}]`)}
	if !DropRequestPath(raw, "plugins.vendor.search.engine") {
		t.Fatal("field of a dotted plugin id was not dropped")
	}
	if got := string(raw["plugins"]); got != `[{"id":"vendor.search"}]` {
		t.Fatalf("plugins = %s", got)
	}
}

func TestLenientParseRemapsAFinalRefusalToTheClientIndex(t *testing.T) {
	body := []byte(`{"tools": [{"type": "computer"}, 123]}`)
	parse := func(candidate []byte) (int, error) {
		var raw struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(candidate, &raw); err != nil {
			return 0, err
		}
		for index, tool := range raw.Tools {
			var object map[string]string
			if json.Unmarshal(tool, &object) != nil {
				return 0, &AdapterError{Status: 400, Message: "tool must be an object", Context: "tools[" + string(rune('0'+index)) + "]"}
			}
			if object["type"] != "function" {
				return 0, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools[" + string(rune('0'+index)) + "].type"}
			}
		}
		return len(raw.Tools), nil
	}
	_, _, _, err := LenientParse(body, true, parse)
	var aerr *AdapterError
	if !errors.As(err, &aerr) || aerr.Context != "tools[1]" {
		t.Fatalf("err = %v", err)
	}
}

func TestDropRequestPathNeverMatchesToolsByID(t *testing.T) {
	raw := map[string]json.RawMessage{
		"tools": json.RawMessage(`[{"type": "function", "id": "engine", "function": {"name": "f"}}, {"type": "openrouter:web_search", "engine": "native"}]`),
	}
	if !DropRequestPath(raw, "tools.engine") {
		t.Fatal("tools.engine was not dropped")
	}
	if got := string(raw["tools"]); got != `[{"type": "function", "id": "engine", "function": {"name": "f"}},{"type":"openrouter:web_search"}]` && !strings.Contains(got, `"id":"engine"`) {
		t.Fatalf("the function tool was removed: %s", got)
	}
	var tools []map[string]any
	_ = json.Unmarshal(raw["tools"], &tools)
	if len(tools) != 2 || tools[1]["engine"] != nil {
		t.Fatalf("tools = %s", raw["tools"])
	}
}

func TestLenientDropPathKeepsLiteralUnknownKeys(t *testing.T) {
	for _, key := range []string{" extra_body ", "x=y"} {
		path, ok := LenientDropPath(unknownRequestParameter(key))
		if !ok || path != key {
			t.Fatalf("%q resolved to %q %v", key, path, ok)
		}
		raw := map[string]json.RawMessage{key: json.RawMessage(`1`), "model": json.RawMessage(`"m"`)}
		if !DropRequestPath(raw, path) || len(raw) != 1 {
			t.Fatalf("%q was not dropped", key)
		}
	}
}

func TestLenientParseBoundsTotalWork(t *testing.T) {
	big := strings.Repeat("x", 4<<20)
	raw := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": big}}}
	for i := 0; i < 20; i++ {
		raw["unknown_"+string(rune('a'+i))] = 1
	}
	body, _ := json.Marshal(raw)
	if _, dropped, _, err := LenientParse(body, true, validateChatBody); err == nil {
		t.Fatalf("a 4 MiB body shed %d fields past the work bound", len(dropped))
	}
}

func TestLenientParseKeepsStrictAnswerForRepeatedKeys(t *testing.T) {
	body := []byte(`{"model":"m","messages":[],"provider":{"zdr":true},"provider":{"order":["a"]},"extra_body":{}}`)
	if _, dropped, _, err := LenientParse(body, true, validateChatBody); err == nil {
		t.Fatalf("a body with a repeated key was re-serialized, dropping %v", dropped)
	}
	for body, want := range map[string]bool{
		`{"a":1,"a":2}`:                 true,
		`{"a":{"b":1,"b":2}}`:           true,
		`{"a":[{"b":1},{"b":2}],"c":1}`: false,
		`{"a":{"b":1},"b":{"a":1}}`:     false,
		`{"a":"a","b":"a"}`:             false,
		`{"a":1e1000,"b":1,"b":2}`:      true,
		`{"a":1e1000}`:                  false,
		`{"a":`:                         true,
	} {
		if got := hasDuplicateKeys([]byte(body)); got != want {
			t.Fatalf("%s: %v", body, got)
		}
	}
}

func TestLenientParseRemapsAfterPluginRemovedByID(t *testing.T) {
	body := []byte(`{"model":"m","messages":[],"plugins":[{"id":"file-parser"},{"id":123}]}`)
	_, _, _, err := LenientParse(body, true, validateChatBody)
	var aerr *AdapterError
	if !errors.As(err, &aerr) || aerr.Context != "plugins[1].id" {
		t.Fatalf("err = %v", err)
	}
}
