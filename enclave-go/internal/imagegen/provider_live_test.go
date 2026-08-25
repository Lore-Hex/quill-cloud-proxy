//go:build live_provider_wave

package imagegen

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveProviderWaveImageModels(t *testing.T) {
	if os.Getenv("TR_LIVE_PROVIDER_WAVE") != "1" {
		t.Skip("set TR_LIVE_PROVIDER_WAVE=1 to run paid provider-wave image smokes")
	}
	keys := ProviderKeys{
		Recraft: os.Getenv("RECRAFT_API_KEY"),
		BFL:     os.Getenv("BFL_API_KEY"),
		Decart:  os.Getenv("DECART_API_KEY"),
	}
	if keys.Recraft == "" || keys.BFL == "" || keys.Decart == "" {
		t.Fatal("RECRAFT_API_KEY, BFL_API_KEY, and DECART_API_KEY are required")
	}
	registry := NewRegistry(keys, nil)
	models := []string{
		"recraft/recraftv4_1_pro",
		"recraft/recraftv4_1_utility_pro",
		"recraft/recraftv4_1",
		"recraft/recraftv4_1_utility",
		"recraft/recraftv4_pro",
		"recraft/recraftv4",
		"recraft/recraftv3",
		"recraft/recraftv2",
		"black-forest-labs/flux-2-klein-4b",
		"black-forest-labs/flux-2-klein-9b",
		"black-forest-labs/flux-2-pro",
		"black-forest-labs/flux-2-max",
		"black-forest-labs/flux-2-flex",
	}
	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			resolved, err := Parse([]byte(`{"model":"` + model + `","prompt":"A small solid blue square centered on a white background."}`))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
			defer cancel()
			result, err := registry.Generate(ctx, resolved, "", "provider-wave-live-"+model)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Images) != 1 || result.Images[0].Width <= 0 || result.Images[0].Height <= 0 {
				t.Fatalf("invalid result metadata: %#v", result)
			}
			t.Logf("generated %s %dx%d", result.Images[0].MediaType, result.Images[0].Width, result.Images[0].Height)
		})
	}

	t.Run("decart/lucy-image-2", func(t *testing.T) {
		input := testPNG(t, 64, 64)
		resolved, err := Parse([]byte(`{"model":"decart/lucy-image-2","prompt":"Turn the square blue.","resolution":"480p","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + input + `"}}]}`))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
		defer cancel()
		result, err := registry.Generate(ctx, resolved, "", "provider-wave-live-decart")
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Images) != 1 || result.Images[0].Width <= 0 || result.Images[0].Height <= 0 {
			t.Fatalf("invalid result metadata: %#v", result)
		}
		t.Logf("generated %s %dx%d", result.Images[0].MediaType, result.Images[0].Width, result.Images[0].Height)
	})
}

func TestLiveNscaleImageModel(t *testing.T) {
	if os.Getenv("TR_LIVE_PROVIDER_WAVE") != "1" {
		t.Skip("set TR_LIVE_PROVIDER_WAVE=1 to run paid provider-wave image smokes")
	}
	key := os.Getenv("NSCALE_API_KEY")
	if key == "" {
		t.Skip("NSCALE_API_KEY not set")
	}
	resolved, err := Parse([]byte(`{"model":"black-forest-labs/flux.1-schnell","prompt":"A small solid blue square centered on a white background."}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	result, err := NewRegistry(ProviderKeys{Nscale: key}, nil).Generate(
		ctx, resolved, "", "nscale-provider-wave-live",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Images) != 1 || result.Images[0].Width != 1024 || result.Images[0].Height != 1024 {
		t.Fatalf("invalid result metadata: %#v", result)
	}
}
