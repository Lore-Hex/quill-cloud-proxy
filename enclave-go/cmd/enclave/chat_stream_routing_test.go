package main

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestChatRoutingMetadataTracksWinnerAtEmission(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		for _, withSettlement := range []bool{false, true} {
			t.Run(fmt.Sprintf("hidden=%t/settlement=%t", hidden, withSettlement), func(t *testing.T) {
				first := llm.InvokeOptions{Model: "first-model", Provider: "first", EndpointID: "first-endpoint"}
				winner := llm.InvokeOptions{Model: "fortanix/glm-5.3-flash", Provider: "fortanix", EndpointID: "fortanix/glm-5.3-flash@fortanix/prepaid"}
				options := []llm.InvokeOptions{first, winner}
				auth := &trustedrouter.Authorization{Model: first.Model, Provider: first.Provider, EndpointID: first.EndpointID, ResponseModel: "private/alias", HidePublicMetadata: hidden, GatewayRegion: "us-central1"}
				selected := newSelectedRouteTracker()
				var control *adapter.StreamControl
				if withSettlement {
					control = &adapter.StreamControl{BeforeTerminal: func(terminal adapter.StreamTerminal) error {
						terminal.UsageFields["cost_microdollars"] = 1
						return terminal.Emit()
					}}
				}
				control = withChatRoutingMetadata(control, auth, selected, options)
				selected.RecordCandidateAttempt(first)
				selected.RecordCandidateAttempt(winner)
				selected.Select(winner)
				fields := map[string]any{"provider_usage": map[string]any{"selected_provider": "untrusted"}}
				writeErr := errors.New("terminal write failed")
				emits := 0
				err := control.BeforeTerminal(adapter.StreamTerminal{UsageFields: fields, Emit: func() error {
					emits++
					routing, _ := fields["provider_usage"].(map[string]any)
					want := map[string]any{
						"router": "direct", "selected_model": winner.Model, "selected_provider": winner.Provider,
						"selected_endpoint": winner.EndpointID, "fallback_candidate_count": 2,
						"upstream_attempt_count": 2, "fallback_attempt_count": 1,
						"contains_prompt_or_completion": false, "gateway_region": "us-central1",
					}
					if hidden {
						want["selected_model"], want["selected_provider"] = "private/alias", "trustedrouter"
						delete(want, "selected_endpoint")
						delete(want, "gateway_region")
					}
					if !reflect.DeepEqual(routing, want) {
						t.Errorf("routing = %#v, want %#v", routing, want)
					}
					if withSettlement && fields["cost_microdollars"] != 1 {
						t.Error("routing changed settlement ordering or cost")
					}
					return writeErr
				}})
				if !errors.Is(err, writeErr) || emits != 1 {
					t.Fatalf("err=%v emits=%d", err, emits)
				}
			})
		}
	}
}

func TestChatRoutingMetadataPreservesTerminalHooks(t *testing.T) {
	auth := &trustedrouter.Authorization{Model: "model", Provider: "provider", EndpointID: "endpoint"}
	selected := newSelectedRouteTracker()
	option := llm.InvokeOptions{Model: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID}
	selected.RecordCandidateAttempt(option)
	selected.Select(option)
	hookErr := errors.New("settlement failed")
	for _, scenario := range []string{"usage", "opt-out", "nil", "error"} {
		t.Run(scenario, func(t *testing.T) {
			var metadata map[string]any
			var afterErr error
			switch scenario {
			case "usage":
				metadata = map[string]any{"usage": map[string]any{"cost_microdollars": 1}}
			case "opt-out":
				metadata = map[string]any{"trusted_router_settlement": "pending"}
			case "error":
				metadata = map[string]any{"usage": map[string]any{"cost_microdollars": 1}}
				afterErr = hookErr
			}
			afterCalls := 0
			control := withChatRoutingMetadata(&adapter.StreamControl{
				BeforeTerminal: func(terminal adapter.StreamTerminal) error { return hookErr },
				AfterTerminal: func(result adapter.StreamResult) (map[string]any, error) {
					afterCalls++
					return metadata, afterErr
				},
			}, auth, selected, []llm.InvokeOptions{option})
			if err := control.BeforeTerminal(adapter.StreamTerminal{Emit: func() error {
				t.Fatal("failed before-terminal hook must not emit")
				return nil
			}}); !errors.Is(err, hookErr) {
				t.Fatal(err)
			}
			got, err := control.AfterTerminal(adapter.StreamResult{})
			if err != afterErr || afterCalls != 1 || !reflect.DeepEqual(got, metadata) {
				t.Fatalf("after hook changed: metadata=%v err=%v calls=%d", got, err, afterCalls)
			}
			fields, _ := got["usage"].(map[string]any)
			routing, _ := fields["provider_usage"].(map[string]any)
			if scenario == "usage" {
				if routing["selected_provider"] != auth.Provider || routing["upstream_attempt_count"] != 1 || routing["fallback_attempt_count"] != 0 || fields["cost_microdollars"] != 1 {
					t.Fatalf("async routing or cost missing: %v", fields)
				}
				if _, present := routing["gateway_region"]; present {
					t.Fatal("invented missing gateway region")
				}
			} else if routing != nil {
				t.Fatal("added routing without successful usage metadata")
			}
		})
	}
}

func TestChatRoutingMetadataLeavesCustomAndUnattributedStreamsUnchanged(t *testing.T) {
	for _, auth := range []*trustedrouter.Authorization{nil, {CustomModel: &trustedrouter.CustomModel{ID: "custom/private"}}} {
		control := &adapter.StreamControl{}
		if got := withChatRoutingMetadata(control, auth, newSelectedRouteTracker(), nil); got != control || got.BeforeTerminal != nil || got.AfterTerminal != nil {
			t.Fatal("added public routing to custom or unattributed stream")
		}
	}
	if got := withChatRoutingMetadata(nil, &trustedrouter.Authorization{}, nil, nil); got != nil {
		t.Fatal("added routing without a route tracker")
	}
	control := withChatRoutingMetadata(nil, &trustedrouter.Authorization{}, newSelectedRouteTracker(), nil)
	emitted := false
	if err := control.BeforeTerminal(adapter.StreamTerminal{Emit: func() error { emitted = true; return nil }}); err != nil || !emitted {
		t.Fatalf("nil usage fields changed emission: %v", err)
	}
}
