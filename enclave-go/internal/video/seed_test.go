package video

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
)

func TestVeniceRejectsSeedAndPayloadOmitsIt(t *testing.T) {
	for _, seed := range []int64{0, 1101} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			req := &CreateRequest{Model: "bytedance/seedance-2.5", Prompt: "A blue cube", Seed: &seed}
			_, queue, _, err := Resolve(req)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := queue["seed"]; ok {
				t.Fatal("Venice queue contains seed")
			}
			resolved, err := ResolveRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.Seed == nil || *resolved.Seed != seed {
				t.Fatal("resolved request lost seed")
			}
			if _, ok := resolved.VeniceQueuePayload()["seed"]; ok {
				t.Fatal("resolved Venice queue contains seed")
			}
			calls := 0
			client := NewVeniceClient("test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(200, "application/json", `{}`), nil
			})})
			if client.Supports(resolved) {
				t.Fatal("Venice supports seed")
			}
			if _, err := client.QuoteResolved(context.Background(), resolved); err == nil {
				t.Fatal("quoted unsupported seed")
			}
			if _, err := client.QueueResolved(context.Background(), resolved); err == nil {
				t.Fatal("queued unsupported seed")
			}
			if _, err := client.Queue(context.Background(), map[string]any{"seed": seed}); err == nil {
				t.Fatal("raw queue accepted seed")
			}
			if calls != 0 {
				t.Fatalf("unsupported seed made %d HTTP calls", calls)
			}
			registry := NewRegistryWithProviders(client, NewBytePlusClient("test", nil))
			providers := registry.Supporting(resolved)
			if len(providers) != 1 || providers[0].ID() != "byteplus" {
				t.Fatalf("seeded routes = %v", providers)
			}
			resolved.Seed = nil
			providers = registry.Supporting(resolved)
			if len(providers) != 2 || providers[0].ID() != "byteplus" || providers[1].ID() != "venice" {
				t.Fatalf("unseeded routes = %v", providers)
			}
		})
	}
}

func TestModelsJSONSeedRequiresEnabledCapableRoute(t *testing.T) {
	all := ProviderKeys{BytePlus: "test", Venice: "test", FAL: "test", Google: "test", MiniMax: "test", AtlasCloud: "test", XAI: "test", Alibaba: "test", LTX: "test", Runway: "test", OpenAI: "test", Kling: "test", Decart: "test"}
	capable := []string{"bytedance/seedance-2.5", "bytedance/seedance-2.0", "bytedance/seedance-2.0-fast", "google/veo-3.1", "google/veo-3.1-fast", "alibaba/wan-2.7", "minimax/h3-max", "decart/lucy-2.5", "decart/lucy-vton-3.5", "decart/lucy-restyle-2"}
	for _, tc := range []struct {
		name     string
		registry *Registry
		seeds    []string
	}{
		{"all", NewRegistry(all, nil), capable},
		{"venice_only", NewRegistry(ProviderKeys{Venice: "test"}, nil), nil},
		{"byteplus_only", NewRegistry(ProviderKeys{BytePlus: "test"}, nil), capable[:3]},
		{"disabled", NewRegistry(ProviderKeys{}, nil), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := ModelsJSON(tc.registry)
			if err != nil {
				t.Fatal(err)
			}
			var catalog struct {
				Data []struct {
					ID         string   `json:"id"`
					Parameters []string `json:"supported_parameters"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &catalog); err != nil {
				t.Fatal(err)
			}
			if len(catalog.Data) != len(Models()) {
				t.Fatal("changed catalog size")
			}
			for i, row := range catalog.Data {
				model := Models()[i]
				if row.ID != model.ID {
					t.Fatal("changed model order")
				}
				want := []string{"prompt", "duration", "resolution", "aspect_ratio", "size"}
				if slices.Contains(tc.seeds, row.ID) {
					want = append(want, "seed")
				}
				if model.SupportsAudio || model.AudioAlwaysOn {
					want = append(want, "generate_audio")
				}
				if model.SupportsImage {
					want = append(want, "frame_images")
				}
				if model.SupportsReferences {
					want = append(want, "input_references")
				}
				if !slices.Equal(row.Parameters, want) {
					t.Errorf("%s parameters = %v, want %v", row.ID, row.Parameters, want)
				}
			}
		})
	}
}
