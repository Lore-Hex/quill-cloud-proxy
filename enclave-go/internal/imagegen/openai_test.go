package imagegen

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestOpenAI25ContractAndUsage(t *testing.T) {
	for _, model := range []string{"openai/gpt-image-2.5-flare", "openai/gpt-image-2.5-sunburst"} {
		t.Run(model, func(t *testing.T) {
			resolved, err := Parse([]byte(`{"model":"` + model + `","prompt":"square","quality":"max","size":"1024x1024"}`))
			if err != nil {
				t.Fatal(err)
			}
			if resolved.MaxOutputTokens() != 32768 {
				t.Fatal("missing conservative output reservation")
			}
			for _, extra := range []string{`,"n":2`, `,"input_references":[{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]`} {
				if _, err := Parse([]byte(`{"model":"` + model + `","prompt":"square"` + extra + `}`)); err == nil {
					t.Fatal("accepted unsupported request")
				}
			}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var request map[string]any
				if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if req.URL.String() != "https://api.openai.com/v1/images/generations" || request["model"] != resolved.Spec.UpstreamID || request["quality"] != "max" || request["response_format"] != nil {
					t.Fatal("incorrect native request")
				}
				body, _ := json.Marshal(map[string]any{
					"data": []map[string]any{{"b64_json": testPNG(t, 1024, 1024)}},
					"usage": map[string]any{"input_tokens": 100, "output_tokens": 196, "total_tokens": 296,
						"input_tokens_details": map[string]any{"text_tokens": 100, "image_tokens": 0, "cached_tokens": 80}},
				})
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			result, err := NewRegistry(ProviderKeys{OpenAI: "test"}, client).Generate(context.Background(), resolved, "", "test")
			if err != nil {
				t.Fatal(err)
			}
			if result.Usage.InputTokens != 100 || result.Usage.CachedInputTokens != 80 || result.Usage.OutputTokens != 196 {
				t.Fatalf("wrong usage: %+v", result.Usage)
			}
		})
	}
}

func TestOpenAIImageUsageRejectsAmbiguousBilling(t *testing.T) {
	for _, details := range []openAIImageInputDetails{
		{TextTokens: 99}, {TextTokens: 100, ImageTokens: 1},
		{TextTokens: 100, CachedTokens: -1}, {TextTokens: 100, CachedTokens: 101},
	} {
		if err := applyOpenAIImageUsage(&Usage{InputTokens: 100}, &details); err == nil {
			t.Fatal("accepted inconsistent billing counters")
		}
	}
}
