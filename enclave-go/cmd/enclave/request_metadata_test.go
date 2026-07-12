package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRequestMetadataObserveModeDropsInvalidFieldsWithoutFailingInference(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "observe")
	var req types.OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{
		"model":"trustedrouter/auto",
		"messages":[{"role":"user","content":"hello"}],
		"tags":["legacy"],
		"user":"`+strings.Repeat("u", 257)+`"
	}`), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	req.OpenRouterMetadata = true
	if err := validateOrObserveRequestMetadata(&req, "log-observe"); err != nil {
		t.Fatalf("validateOrObserveRequestMetadata: %v", err)
	}
	if req.Tags != nil || req.User != "" {
		t.Fatalf("invalid metadata was not dropped: %#v", req)
	}
	if !req.OpenRouterMetadata {
		t.Fatal("router metadata response opt-in should survive attribution cleanup")
	}
	if len(req.Messages) != 1 {
		t.Fatal("inference body was changed")
	}
}

func TestRequestMetadataObserveModeAcceptsLegacyNonURLReferer(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "")
	req := &types.OpenAIChatRequest{
		HTTPReferer: "legacy-app-name",
		Messages:    []types.OpenAIChatMessage{{Role: "user", Content: "hello"}},
	}
	if err := validateOrObserveRequestMetadata(req, "log-referer"); err != nil {
		t.Fatalf("validateOrObserveRequestMetadata: %v", err)
	}
	if req.HTTPReferer != "" || len(req.Messages) != 1 {
		t.Fatalf("request = %#v", req)
	}
}

func TestRequestMetadataKeepsExisting256CharacterCompatibility(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
	req := &types.OpenAIChatRequest{
		User:      strings.Repeat("u", 200),
		SessionID: strings.Repeat("s", 200),
	}
	if err := validateOrObserveRequestMetadata(req, "log-compatible"); err != nil {
		t.Fatalf("200-character identifiers must remain accepted: %v", err)
	}
}

func TestRequestMetadataEnforceModeReturnsStableValidationErrors(t *testing.T) {
	t.Setenv("TR_REQUEST_METADATA_ENFORCEMENT", "enforce")
	var req types.OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{"tags":["legacy"]}`), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := validateOrObserveRequestMetadata(&req, "log-enforce"); err == nil {
		t.Fatal("expected invalid tags error")
	}

	req = types.OpenAIChatRequest{HTTPReferer: "not-a-url"}
	if err := validateOrObserveRequestMetadata(&req, "log-enforce"); err == nil {
		t.Fatal("expected invalid attribution error")
	}
}
