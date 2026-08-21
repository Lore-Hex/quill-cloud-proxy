package imagegen

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"testing"
)

func TestModelRegistryIsExactAndDefensivelyCopied(t *testing.T) {
	want := []string{
		"google/gemini-3.1-flash-image",
		"google/gemini-3.1-flash-image-preview",
		"openai/gpt-image-1",
		"openai/gpt-image-1-mini",
		"openai/gpt-image-2",
		"x-ai/grok-imagine-image-2.0",
		"x-ai/grok-imagine-image-quality",
	}
	if got := ModelIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("model ids = %#v, want %#v", got, want)
	}
	spec, ok := Spec("openai/gpt-image-2")
	if !ok {
		t.Fatal("missing GPT Image 2 spec")
	}
	spec.AspectRatios[0] = "mutated"
	again, _ := Spec("openai/gpt-image-2")
	if again.AspectRatios[0] == "mutated" {
		t.Fatal("caller mutated the registry")
	}
}

func TestMaximumOutputReservationsComeFromTheResolvedModel(t *testing.T) {
	for _, tt := range []struct {
		body string
		want int
	}{
		{body: `{"model":"google/gemini-3.1-flash-image","prompt":"cat","resolution":"2K"}`, want: 1680},
		{body: `{"model":"openai/gpt-image-2","prompt":"cat","n":3}`, want: 24_000},
		{body: `{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat"}`, want: 1},
	} {
		resolved, err := Parse([]byte(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		if got := resolved.MaxOutputTokens(); got != tt.want {
			t.Fatalf("MaxOutputTokens() = %d, want %d for %s", got, tt.want, tt.body)
		}
	}
}

func TestParseUsesModelSpecForNormalizedParameters(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantRes     string
		wantAspect  string
		wantQuality string
		wantFormat  string
		wantQuote   int
		wantParam   string
	}{
		{
			name:    "gemini native pixels",
			body:    `{"model":"google/gemini-3.1-flash-image","prompt":"cat","size":"2752x1536","quality":"high"}`,
			wantRes: "2K", wantAspect: "16:9",
		},
		{
			name:      "gemini size conflict",
			body:      `{"model":"google/gemini-3.1-flash-image","prompt":"cat","size":"2K","resolution":"1K"}`,
			wantParam: "size",
		},
		{
			name:       "openai normalized",
			body:       `{"model":"openai/gpt-image-2","prompt":"cat","aspect_ratio":"16:9","quality":"high","output_format":"webp","background":"opaque","output_compression":72,"n":10,"provider":{"options":{"openai":{"moderation":"auto"}}}}`,
			wantAspect: "16:9", wantQuality: "high", wantFormat: "webp",
		},
		{
			name:       "openai explicit pixels",
			body:       `{"model":"openai/gpt-image-2","prompt":"cat","size":"1536x864"}`,
			wantAspect: "16:9", wantQuality: "auto", wantFormat: "png",
		},
		{
			name:      "openai references not advertised",
			body:      `{"model":"openai/gpt-image-1","prompt":"cat","input_references":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}`,
			wantParam: "input_references",
		},
		{
			name:      "transparent jpeg conflict",
			body:      `{"model":"openai/gpt-image-1","prompt":"cat","background":"transparent","output_format":"jpeg"}`,
			wantParam: "background",
		},
		{
			name:    "grok defaults",
			body:    `{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat"}`,
			wantRes: "1K", wantAspect: "auto", wantQuality: "medium", wantQuote: 63_300,
		},
		{
			name:    "grok low 2k",
			body:    `{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat","resolution":"2k","quality":"low"}`,
			wantRes: "2K", wantAspect: "auto", wantQuality: "low", wantQuote: 63_300,
		},
		{
			name:      "unknown passthrough",
			body:      `{"model":"openai/gpt-image-2","prompt":"cat","provider":{"options":{"openai":{"secret":true}}}}`,
			wantParam: "provider.options.openai.secret",
		},
		{
			name:       "completion-only streaming",
			body:       `{"model":"openai/gpt-image-2","prompt":"cat","stream":true}`,
			wantAspect: "auto", wantQuality: "auto", wantFormat: "png",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.body))
			if tt.wantParam != "" {
				if err == nil {
					t.Fatalf("expected error, got %#v", got)
				}
				requestErr, ok := err.(*RequestError)
				if !ok || requestErr.Param != tt.wantParam {
					t.Fatalf("error = %#v, want param %q", err, tt.wantParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Resolution != tt.wantRes || got.AspectRatio != tt.wantAspect ||
				got.Quality != tt.wantQuality || got.Format != tt.wantFormat {
				t.Fatalf("resolved = res=%q aspect=%q quality=%q format=%q", got.Resolution, got.AspectRatio, got.Quality, got.Format)
			}
			if quote := got.FixedCustomerCostMicrodollars(); quote != tt.wantQuote {
				t.Fatalf("quote = %d, want %d", quote, tt.wantQuote)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestNativeProviderTranslationAndValidatedResponse(t *testing.T) {
	for _, tt := range []struct {
		name       string
		request    string
		wantHost   string
		wantBody   map[string]any
		managedKey string
		wantMedia  string
		width      int
		height     int
	}{
		{
			name:     "openai",
			request:  `{"model":"openai/gpt-image-2","prompt":"cat","aspect_ratio":"16:9","quality":"high","output_format":"png","output_compression":72,"n":2,"provider":{"options":{"openai":{"moderation":"auto"}}}}`,
			wantHost: "api.openai.com", managedKey: "openai-key", wantMedia: "image/png",
			width: 1536, height: 864,
			wantBody: map[string]any{"model": "gpt-image-2", "prompt": "cat", "n": float64(2), "response_format": "b64_json", "size": "1536x864", "quality": "high", "output_format": "png", "moderation": "auto"},
		},
		{
			name:     "xai",
			request:  `{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat","resolution":"2K","quality":"low","aspect_ratio":"3:2"}`,
			wantHost: "api.x.ai", managedKey: "xai-key", wantMedia: "image/png",
			width: 2496, height: 1664,
			wantBody: map[string]any{"model": "grok-imagine-image-2.0", "prompt": "cat", "n": float64(1), "response_format": "b64_json", "resolution": "2k", "quality": "low", "aspect_ratio": "3:2"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := Parse([]byte(tt.request))
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != tt.wantHost {
					t.Fatalf("host = %q", req.URL.Host)
				}
				if req.Header.Get("Authorization") != "Bearer "+tt.managedKey {
					t.Fatalf("authorization header missing")
				}
				if req.Header.Get("Idempotency-Key") != "image-one" {
					t.Fatalf("idempotency = %q", req.Header.Get("Idempotency-Key"))
				}
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(body, tt.wantBody) {
					t.Fatalf("body = %#v, want %#v", body, tt.wantBody)
				}
				payload, _ := json.Marshal(map[string]any{
					"created": 123, "data": []map[string]any{{"b64_json": testPNG(t, tt.width, tt.height)}},
					"usage": map[string]any{"input_tokens": 7, "output_tokens": 11, "total_tokens": 18},
				})
				return &http.Response{
					StatusCode: 200, Body: io.NopCloser(bytes.NewReader(payload)), Header: make(http.Header),
				}, nil
			})}
			keys := ProviderKeys{}
			if resolved.Spec.Provider == "openai" {
				keys.OpenAI = tt.managedKey
			} else {
				keys.XAI = tt.managedKey
			}
			result, err := NewRegistry(keys, client).Generate(context.Background(), resolved, "", "image-one")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(result.Images) != 1 || result.Images[0].MediaType != tt.wantMedia ||
				result.Usage.InputTokens != 7 || result.Usage.OutputTokens != 11 {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestOpenAICompressionIsForwardedOnlyForCompressibleFormats(t *testing.T) {
	for _, tt := range []struct {
		format string
		want   bool
	}{
		{format: "png", want: false},
		{format: "jpeg", want: true},
		{format: "webp", want: true},
	} {
		t.Run(tt.format, func(t *testing.T) {
			resolved, err := Parse([]byte(`{"model":"openai/gpt-image-2","prompt":"cat","output_format":"` + tt.format + `","output_compression":72}`))
			if err != nil {
				t.Fatal(err)
			}
			_, payload, err := nativeRequest(resolved)
			if err != nil {
				t.Fatal(err)
			}
			_, got := payload["output_compression"]
			if got != tt.want {
				t.Fatalf("output_compression present = %v, want %v; payload=%#v", got, tt.want, payload)
			}
		})
	}
}

func TestNativeProviderOutputShapeMustMatchTheNormalizedRequest(t *testing.T) {
	for _, tt := range []struct {
		body      string
		generated GeneratedImage
		wantError bool
	}{
		{
			body:      `{"model":"openai/gpt-image-2","prompt":"cat","aspect_ratio":"16:9"}`,
			generated: GeneratedImage{Width: 1024, Height: 1024}, wantError: true,
		},
		{
			body:      `{"model":"openai/gpt-image-2","prompt":"cat","aspect_ratio":"16:9"}`,
			generated: GeneratedImage{Width: 1536, Height: 864},
		},
		{
			body:      `{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat","resolution":"1K","aspect_ratio":"3:2"}`,
			generated: GeneratedImage{Width: 1024, Height: 1024}, wantError: true,
		},
		{
			body:      `{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat","resolution":"1K","aspect_ratio":"3:2"}`,
			generated: GeneratedImage{Width: 1248, Height: 832},
		},
	} {
		resolved, err := Parse([]byte(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		err = validateOutputShape(resolved, &tt.generated)
		if (err != nil) != tt.wantError {
			t.Fatalf("validateOutputShape(%s, %#v) = %v", tt.body, tt.generated, err)
		}
	}
}

func TestNativeProviderRejectsRedirectsAndCorruptImages(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"openai/gpt-image-1-mini","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		payload := `{"data":[{"b64_json":"bm90LWFuLWltYWdl"}],"usage":{"input_tokens":1,"output_tokens":1}}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(payload)), Header: make(http.Header)}, nil
	})}
	if _, err := NewRegistry(ProviderKeys{OpenAI: "key"}, client).Generate(t.Context(), resolved, "", ""); err == nil {
		t.Fatal("accepted corrupt image bytes")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	caller := &http.Client{Jar: jar}
	registry := NewRegistry(ProviderKeys{OpenAI: "key"}, caller)
	if registry.http.Jar != nil || caller.Jar != jar {
		t.Fatal("registry retained the caller cookie jar or mutated the caller")
	}
	redirectReq, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err := registry.http.CheckRedirect(redirectReq, []*http.Request{redirectReq}); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v", err)
	}
}

func TestNativeProviderRejectsTrailingJSON(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"openai/gpt-image-1-mini","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"data":  []map[string]any{{"b64_json": testPNG(t, 2, 2)}},
		"usage": map[string]any{"input_tokens": 1, "output_tokens": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(append(payload, []byte(` {}`)...))),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := NewRegistry(ProviderKeys{OpenAI: "key"}, client).Generate(t.Context(), resolved, "", ""); err == nil {
		t.Fatal("accepted trailing provider JSON")
	}
}

func TestNativeProviderRejectsInvalidUsage(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"openai/gpt-image-1-mini","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"data": []map[string]any{{"b64_json": testPNG(t, 1024, 1024)}},
		"usage": map[string]any{
			"input_tokens": 8, "output_tokens": 13, "total_tokens": 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := NewRegistry(ProviderKeys{OpenAI: "key"}, client).Generate(t.Context(), resolved, "", ""); err == nil {
		t.Fatal("accepted a provider total smaller than input plus output usage")
	}
}

func TestNativeProviderUsesThePerCallBYOKCredential(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"data":  []map[string]any{{"b64_json": testPNG(t, 1024, 1024)}},
		"usage": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer workspace-xai-key" {
			t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Header:     make(http.Header),
		}, nil
	})}
	registry := NewRegistry(ProviderKeys{}, client)
	if _, err := registry.Generate(
		t.Context(), resolved, "workspace-xai-key", "byok-image-one",
	); err != nil {
		t.Fatalf("Generate with BYOK key: %v", err)
	}
}

func testPNG(t *testing.T, width, height int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}
