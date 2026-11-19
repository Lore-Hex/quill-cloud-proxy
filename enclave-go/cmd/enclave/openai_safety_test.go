package main

import (
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestOpenAISafetyIdentityFollowsActualRoute(t *testing.T) {
	digest := strings.Repeat("7b", 32)
	a := &trustedrouter.Authorization{
		OpenAISafetyIdentifier: digest, WorkspaceID: "test-workspace",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Provider: "openrouter", UsageType: "Credits"},
			{Provider: "openai", UsageType: "Credits"},
		},
	}
	opts, err := invokeOptionsForAuthorization(t.Context(), nil, a)
	if err != nil || len(opts) != 2 || opts[0].OpenAISafetyIdentifier != "" || opts[1].OpenAISafetyIdentifier != digest {
		t.Fatal("identifier did not follow direct OpenAI fallback", err)
	}
	a.OpenAISafetyIdentifier = "caller@example.invalid"
	legacy := openAISafetyIdentifier("openai", a)
	if len(legacy) != 64 || legacy == digest {
		t.Fatal("invalid legacy workspace digest")
	}
	a.OpenAISafetyIdentifier = ""
	if legacy != openAISafetyIdentifier("openai", a) {
		t.Fatal("invalid metadata should never reach provider")
	}
	a.WorkspaceID = "other-workspace"
	if legacy == openAISafetyIdentifier("openai", a) {
		t.Fatal("workspace collision")
	}
}
