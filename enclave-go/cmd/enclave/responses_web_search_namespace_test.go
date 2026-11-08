package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestResponsesWebSearchStreamedCallCarriesDeclaredName(t *testing.T) {
	meta := &types.ResponseRequestMeta{FunctionNamespaces: map[string]types.ResponseNamespacedFunction{
		"crm__search": {Namespace: "crm", Name: "search"},
	}}
	item := responseFunctionCallStreamingItem("resp_1", 0, types.ToolCall{CallID: "call_1", Name: "crm__search", Arguments: "{}"}, meta)
	if item["name"] != "search" || item["namespace"] != "crm" {
		t.Fatalf("namespaced item = %v", item)
	}
	item = responseFunctionCallStreamingItem("resp_1", 1, types.ToolCall{CallID: "call_2", Name: "search", Arguments: "{}"}, meta)
	if _, ok := item["namespace"]; ok || item["name"] != "search" {
		t.Fatalf("top-level item = %v", item)
	}
	if item := responseFunctionCallStreamingItem("resp_1", 2, types.ToolCall{CallID: "call_3", Name: "x"}, nil); item["name"] != "x" {
		t.Fatalf("no meta = %v", item)
	}
}
