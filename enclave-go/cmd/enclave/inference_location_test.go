package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func locationFixture() (*trustedrouter.Authorization, *selectedRouteTracker) {
	auth := &trustedrouter.Authorization{
		Model: "model", Provider: "telnyx", EndpointID: "telnyx-credits", Region: "us-central1",
		InferenceLocation: &trustedrouter.InferenceLocationMetadata{AdvertisedRegions: []string{"United States", "Europe"}, AdvertisedRegionScope: "model_default_tier"},
		RouteCandidates: []trustedrouter.RouteCandidate{{Model: "model", Provider: "scaleway", EndpointID: "scaleway-credits",
			InferenceLocation: &trustedrouter.InferenceLocationMetadata{ProviderDeclaredLocations: []string{"France (Paris)"}}}},
	}
	tracker := newSelectedRouteTracker()
	tracker.Select(llm.InvokeOptions{Model: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID})
	return auth, tracker
}

func TestInferenceLocationUsesWinningEndpointAndNeverGatewayRegion(t *testing.T) {
	auth, _ := locationFixture()
	got := selectedInferenceLocation(auth, "scaleway-credits", "scaleway", "model")
	if got == nil || len(got.AdvertisedRegions) != 0 || len(got.ProviderDeclaredLocations) != 1 || got.ServingRegion != nil || got.ServingRegionStatus != "not_reported" {
		t.Fatalf("fallback geography: %+v", got)
	}
	for _, ids := range [][3]string{{"", "telnyx", "model"}, {"telnyx-credits", "scaleway", "model"}, {"telnyx-credits", "telnyx", "other"}} {
		if selectedInferenceLocation(auth, ids[0], ids[1], ids[2]) != nil {
			t.Fatal("mismatched route got geography")
		}
	}
	region := "us-central1"
	auth.InferenceLocation.ServingRegion = &region
	auth.InferenceLocation.RegionPinningEnforced = true
	got = selectedInferenceLocation(auth, auth.EndpointID, auth.Provider, auth.Model)
	if got.ServingRegion != nil || got.RegionPinningEnforced || auth.InferenceLocation.ServingRegion == nil {
		t.Fatal("catalog claim treated as serving receipt, or auth mutated")
	}
}

func TestInferenceLocationRedactionAndOldControlPlane(t *testing.T) {
	for _, kind := range []string{"private", "custom", "legacy", "nil"} {
		t.Run(kind, func(t *testing.T) {
			auth, _ := locationFixture()
			switch kind {
			case "private":
				auth.HidePublicMetadata = true
			case "custom":
				auth.CustomModel = &trustedrouter.CustomModel{ID: "trustedrouter/user-secret"}
			case "legacy":
				auth.InferenceLocation = nil
			case "nil":
				auth = nil
			}
			usage := map[string]any{"inference_location": "untrusted upstream claim", "cost_microdollars": 123}
			annotateInferenceLocation(usage, auth, "telnyx-credits", "telnyx", "model")
			if _, ok := usage["inference_location"]; ok || usage["cost_microdollars"] != 123 {
				t.Fatalf("redaction changed accounting or leaked location: %#v", usage)
			}
		})
	}
}

func TestInferenceLocationNonStreamingPreservesCost(t *testing.T) {
	auth, tracker := locationFixture()
	body, err := annotateSettledResponseMetadata([]byte(`{"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":3}}`), auth,
		&trustedrouter.SettleResult{Model: auth.Model, Provider: auth.Provider, CostMicrodollars: 9}, tracker, nil, adapter.StreamResult{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"serving_region":null`)) || !bytes.Contains(body, []byte(`"cost_microdollars":9`)) || !bytes.Contains(body, []byte(`"completion_tokens":3`)) {
		t.Fatalf("response: %s", body)
	}
}

func TestInferenceLocationStreamingEmitsAfterExistingHook(t *testing.T) {
	for _, responses := range []bool{false, true} {
		auth, tracker := locationFixture()
		calls := 0
		control := withInferenceLocation(&adapter.StreamControl{BeforeTerminal: func(terminal adapter.StreamTerminal) error {
			calls++
			terminal.UsageFields["cost_microdollars"] = 7
			return terminal.Emit()
		}}, auth, tracker)
		input := "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3,\"total_tokens\":14}}\n\ndata: [DONE]\n\n"
		var out bytes.Buffer
		var err error
		if responses {
			_, err = adapter.TransformResponsesStreamControlled(strings.NewReader(input), &out, "resp_test", "model", 11, nil, nil, nil, control)
		} else {
			_, err = adapter.TransformStreamCaptureControlled(strings.NewReader(input), &out, "chat_test", "model", true, nil, nil, control)
		}
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 || !strings.Contains(out.String(), `"inference_location":`) || !strings.Contains(out.String(), `"serving_region":null`) || !strings.Contains(out.String(), `"cost_microdollars":7`) || strings.Count(out.String(), "[DONE]") != 1 {
			t.Fatalf("responses=%v calls=%d output=%s", responses, calls, out.String())
		}
		// The wire contract is JSON, with explicit null rather than an empty
		// string that might be mistaken for a default region.
		wire, _ := json.Marshal(auth.InferenceLocation)
		if !bytes.Contains(wire, []byte(`"serving_region":null`)) {
			t.Fatal(string(wire))
		}
	}
}
