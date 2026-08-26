package types

import (
	"encoding/json"
	"testing"
)

func TestNormalizeFallbackRoutingPromotesTopLevelAliasAndDropsFallbackModels(t *testing.T) {
	var req OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{
		"model":"openai/gpt-oss-20b",
		"models":["google/gemini-2.0-flash-lite"],
		"allow_fallbacks":false,
		"messages":[{"role":"user","content":"hello"}]
	}`), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}

	if err := req.NormalizeFallbackRouting(); err != nil {
		t.Fatalf("NormalizeFallbackRouting: %v", err)
	}
	if req.AllowFallbacks != nil {
		t.Fatal("top-level compatibility field must be consumed before provider invocation")
	}
	if req.Provider == nil || req.Provider.AllowFallbacks == nil || *req.Provider.AllowFallbacks {
		t.Fatalf("provider.allow_fallbacks = %#v, want false", req.Provider)
	}
	if len(req.Models) != 0 {
		t.Fatalf("disabled fallback models survived normalization: %#v", req.Models)
	}
	if req.FallbacksAllowed() {
		t.Fatal("FallbacksAllowed returned true after explicit disable")
	}
}

func TestNormalizeFallbackRoutingRejectsConflictingControls(t *testing.T) {
	var req OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{
		"model":"openai/gpt-oss-20b",
		"allow_fallbacks":false,
		"provider":{"allow_fallbacks":true},
		"messages":[{"role":"user","content":"hello"}]
	}`), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}

	if err := req.NormalizeFallbackRouting(); err == nil {
		t.Fatal("conflicting fallback controls must fail closed")
	}
}

func TestNormalizeFallbackRoutingKeepsEnabledFallbackModels(t *testing.T) {
	allow := true
	req := OpenAIChatRequest{
		Model:          "openai/gpt-oss-20b",
		Models:         []string{"openai/gpt-oss-120b"},
		AllowFallbacks: &allow,
	}

	if err := req.NormalizeFallbackRouting(); err != nil {
		t.Fatalf("NormalizeFallbackRouting: %v", err)
	}
	if len(req.Models) != 1 || req.Models[0] != "openai/gpt-oss-120b" {
		t.Fatalf("enabled fallback models changed: %#v", req.Models)
	}
	if !req.FallbacksAllowed() {
		t.Fatal("FallbacksAllowed returned false for enabled fallbacks")
	}
}

func TestNormalizeFallbackRoutingUsesFirstModelAsPrimaryWhenFallbacksDisabled(t *testing.T) {
	allow := false
	req := OpenAIChatRequest{
		Models: []string{
			"openai/gpt-oss-20b",
			"google/gemini-2.0-flash-lite",
		},
		AllowFallbacks: &allow,
	}

	if err := req.NormalizeFallbackRouting(); err != nil {
		t.Fatalf("NormalizeFallbackRouting: %v", err)
	}
	if req.Model != "openai/gpt-oss-20b" {
		t.Fatalf("primary model = %q, want first models entry", req.Model)
	}
	if len(req.Models) != 0 {
		t.Fatalf("disabled fallback models survived normalization: %#v", req.Models)
	}
}
