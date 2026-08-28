package imagegen

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"reflect"
	"testing"
)

func TestModelRegistryIsExactAndDefensivelyCopied(t *testing.T) {
	want := []string{
		"black-forest-labs/flux-2-flex",
		"black-forest-labs/flux-2-klein-4b",
		"black-forest-labs/flux-2-klein-9b",
		"black-forest-labs/flux-2-max",
		"black-forest-labs/flux-2-pro",
		"black-forest-labs/flux.1-schnell",
		"decart/lucy-image-2",
		"google/gemini-3.1-flash-image",
		"google/gemini-3.1-flash-image-preview",
		"krea/krea-2-medium",
		"openai/gpt-image-1",
		"openai/gpt-image-1-mini",
		"openai/gpt-image-2",
		"recraft/recraftv2",
		"recraft/recraftv3",
		"recraft/recraftv4",
		"recraft/recraftv4_1",
		"recraft/recraftv4_1_pro",
		"recraft/recraftv4_1_utility",
		"recraft/recraftv4_1_utility_pro",
		"recraft/recraftv4_pro",
		"riverflow/riverflow-2-fast",
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
			name:       "recraft fixed price",
			body:       `{"model":"recraft/recraftv4_1","prompt":"cat"}`,
			wantRes:    "1K",
			wantAspect: "1:1",
			wantQuote:  36_925,
		},
		{
			name:       "bfl fixed price",
			body:       `{"model":"black-forest-labs/flux-2-klein-4b","prompt":"cat"}`,
			wantRes:    "1K",
			wantAspect: "1:1",
			wantFormat: "jpeg",
			wantQuote:  14_770,
		},
		{
			name:       "nscale per megapixel fixed price",
			body:       `{"model":"black-forest-labs/flux.1-schnell","prompt":"cat"}`,
			wantRes:    "1K",
			wantAspect: "1:1",
			wantFormat: "png",
			wantQuote:  1_440,
		},
		{
			name:       "krea fixed price",
			body:       `{"model":"krea/krea-2-medium","prompt":"cat"}`,
			wantRes:    "1K",
			wantAspect: "1:1",
			wantQuote:  31_650,
		},
		{
			name:      "decart requires a reference",
			body:      `{"model":"decart/lucy-image-2","prompt":"edit it"}`,
			wantParam: "input_references",
		},
		{
			name:    "decart fixed price",
			body:    `{"model":"decart/lucy-image-2","prompt":"edit it","resolution":"480p","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,aW1hZ2U="}}]}`,
			wantRes: "480p", wantQuote: 10_550,
		},
		{
			name:    "decart resolution is case insensitive",
			body:    `{"model":"decart/lucy-image-2","prompt":"edit it","resolution":"720P","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,aW1hZ2U="}}]}`,
			wantRes: "720p", wantQuote: 21_100,
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
		{
			name:     "recraft",
			request:  `{"model":"recraft/recraftv4_1","prompt":"cat"}`,
			wantHost: "external.api.recraft.ai", managedKey: "recraft-key", wantMedia: "image/png",
			width: 1024, height: 1024,
			wantBody: map[string]any{"model": "recraftv4_1", "prompt": "cat", "n": float64(1), "response_format": "b64_json", "size": "1024x1024"},
		},
		{
			name:     "nscale",
			request:  `{"model":"black-forest-labs/flux.1-schnell","prompt":"cat"}`,
			wantHost: "inference.api.nscale.com", managedKey: "nscale-key", wantMedia: "image/png",
			width: 1024, height: 1024,
			wantBody: map[string]any{"model": "black-forest-labs/FLUX.1-schnell", "prompt": "cat", "n": float64(1), "size": "1024x1024"},
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
			switch resolved.Spec.Provider {
			case "openai":
				keys.OpenAI = tt.managedKey
			case "grok":
				keys.XAI = tt.managedKey
			case "recraft":
				keys.Recraft = tt.managedKey
			case "nscale":
				keys.Nscale = tt.managedKey
			default:
				t.Fatalf("unhandled provider %q", resolved.Spec.Provider)
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

func TestBFLUsesProviderReturnedRegionalPollingURL(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"black-forest-labs/flux-2-klein-4b","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		response := func(status int, body []byte) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
		}
		switch requests {
		case 1:
			if req.Method != http.MethodPost || req.URL.String() != "https://api.bfl.ai/v1/flux-2-klein-4b" {
				t.Fatalf("submit request = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("x-key") != "bfl-key" || req.Header.Get("Idempotency-Key") != "bfl-one" {
				t.Fatalf("submit headers = %#v", req.Header)
			}
			return response(200, []byte(`{"id":"job-one","polling_url":"https://api.eu2.bfl.ai/v1/get_result?id=job-one"}`))
		case 2:
			if req.Method != http.MethodGet || req.URL.String() != "https://api.eu2.bfl.ai/v1/get_result?id=job-one" {
				t.Fatalf("poll request = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("x-key") != "bfl-key" {
				t.Fatalf("poll x-key = %q", req.Header.Get("x-key"))
			}
			return response(200, []byte(`{"status":"Ready","result":{"sample":"https://delivery.eu2.bfl.ai/generated/job-one.jpg?sig=short-lived"}}`))
		case 3:
			if req.Method != http.MethodGet || req.URL.Host != "delivery.eu2.bfl.ai" {
				t.Fatalf("download request = %s %s", req.Method, req.URL)
			}
			return response(200, testJPEGBytes(t, 1024, 1024))
		default:
			t.Fatalf("unexpected request %d: %s", requests, req.URL)
			return nil, nil
		}
	})}
	result, err := NewRegistry(ProviderKeys{BFL: "bfl-key"}, client).Generate(
		t.Context(), resolved, "", "bfl-one",
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if requests != 3 || len(result.Images) != 1 || result.Images[0].MediaType != "image/jpeg" {
		t.Fatalf("requests=%d result=%#v", requests, result)
	}
}

func TestBFLPollingBacksOffAcrossTransientStatus(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"black-forest-labs/flux-2-klein-4b","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		response := func(status int, body []byte) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
		}
		switch requests {
		case 1:
			return response(200, []byte(`{"id":"job-one","polling_url":"https://api.bfl.ai/v1/get_result?id=job-one"}`))
		case 2:
			return response(http.StatusTooManyRequests, []byte(`{"message":"slow down"}`))
		case 3:
			return response(200, []byte(`{"status":"Ready","result":{"sample":"https://delivery.bfl.ai/generated/job-one.jpg"}}`))
		case 4:
			return response(200, testJPEGBytes(t, 1024, 1024))
		default:
			t.Fatalf("unexpected request %d: %s", requests, req.URL)
			return nil, nil
		}
	})}
	result, err := NewRegistry(ProviderKeys{BFL: "bfl-key"}, client).Generate(
		t.Context(), resolved, "", "bfl-retry",
	)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 4 || len(result.Images) != 1 {
		t.Fatalf("requests=%d result=%#v", requests, result)
	}
}

func TestBFLRejectsUntrustedOrMismatchedPollingURLs(t *testing.T) {
	for _, raw := range []string{
		"https://evil.example/v1/get_result?id=job-one",
		"http://api.eu2.bfl.ai/v1/get_result?id=job-one",
		"https://api.eu2.bfl.ai/v1/other?id=job-one",
		"https://api.eu2.bfl.ai/v1/get_result?id=another",
		"https://api.eu2.bfl.ai/v1/get_result?id=job-one&next=https://evil.example",
		"https://api.eu2.bfl.ai:8443/v1/get_result?id=job-one",
		"https://user@api.eu2.bfl.ai/v1/get_result?id=job-one",
	} {
		if got, err := validateBFLPollingURL(raw, "job-one"); err == nil {
			t.Fatalf("accepted polling URL %q as %q", raw, got)
		}
	}
	got, err := validateBFLPollingURL("https://api.eu2.bfl.ai/v1/get_result?id=job-one", "job-one")
	if err != nil || got == "" {
		t.Fatalf("rejected valid polling URL: got=%q err=%v", got, err)
	}
}

func TestDecartUsesValidatedMultipartImageInput(t *testing.T) {
	input := testPNG(t, 8, 8)
	resolved, err := Parse([]byte(`{"model":"decart/lucy-image-2","prompt":"make it blue","resolution":"480p","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + input + `"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.String() != "https://api.decart.ai/v1/generate/lucy-image-2" {
			t.Fatalf("request = %s %s", req.Method, req.URL)
		}
		if req.Header.Get("X-API-KEY") != "decart-key" || req.Header.Get("Idempotency-Key") != "decart-one" {
			t.Fatalf("headers = %#v", req.Header)
		}
		_, params, parseErr := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		reader := multipart.NewReader(req.Body, params["boundary"])
		fields := map[string][]byte{}
		for {
			part, nextErr := reader.NextPart()
			if nextErr == io.EOF {
				break
			}
			if nextErr != nil {
				t.Fatal(nextErr)
			}
			fields[part.FormName()], nextErr = io.ReadAll(part)
			if nextErr != nil {
				t.Fatal(nextErr)
			}
		}
		if string(fields["prompt"]) != "make it blue" || string(fields["resolution"]) != "480p" {
			t.Fatalf("multipart fields = %#v", fields)
		}
		if _, _, decodeErr := image.DecodeConfig(bytes.NewReader(fields["data"])); decodeErr != nil {
			t.Fatalf("data field is not a normalized image: %v", decodeErr)
		}
		output, _ := base64.StdEncoding.DecodeString(testPNG(t, 512, 512))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(output)), Header: make(http.Header)}, nil
	})}
	result, err := NewRegistry(ProviderKeys{Decart: "decart-key"}, client).Generate(
		t.Context(), resolved, "", "decart-one",
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Images) != 1 || result.Images[0].MediaType != "image/png" {
		t.Fatalf("result = %#v", result)
	}
}

func TestKreaSubmitsPollsAndDownloadsModelResult(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"krea/krea-2-medium","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	dataURL := "data:image/png;base64," + testPNG(t, 1024, 1024)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		response := func(status int, value any) (*http.Response, error) {
			body, _ := json.Marshal(value)
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}
		switch requests {
		case 1:
			if req.Method != http.MethodPost || req.URL.String() != "https://api.krea.ai/generate/image/krea/krea-2/medium" {
				t.Fatalf("submit = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("Authorization") != "Bearer krea-key" ||
				req.Header.Get("Idempotency-Key") != "krea-one" ||
				req.Header.Get("X-Api-Zero-Data-Retention") != "" {
				t.Fatalf("submit headers = %#v", req.Header)
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"prompt": "cat", "aspect_ratio": "1:1", "resolution": "1K",
			}
			if !reflect.DeepEqual(body, want) {
				t.Fatalf("submit body = %#v, want %#v", body, want)
			}
			return response(200, map[string]any{"job_id": "job-one", "status": "queued"})
		case 2:
			if req.Method != http.MethodGet || req.URL.String() != "https://api.krea.ai/jobs/job-one" {
				t.Fatalf("poll = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("Authorization") != "Bearer krea-key" {
				t.Fatalf("poll authorization = %q", req.Header.Get("Authorization"))
			}
			return response(200, map[string]any{
				"job_id": "job-one", "status": "completed",
				"result": map[string]any{"urls": []map[string]any{
					{"type": "preview", "url": "data:image/png;base64,ignored"},
					{"type": "model", "url": dataURL},
				}},
			})
		default:
			t.Fatalf("unexpected request %d: %s", requests, req.URL)
			return nil, nil
		}
	})}
	result, err := NewRegistry(ProviderKeys{Krea: "krea-key"}, client).Generate(
		t.Context(), resolved, "", "krea-one",
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if requests != 2 || len(result.Images) != 1 || result.Images[0].MediaType != "image/png" {
		t.Fatalf("requests=%d result=%#v", requests, result)
	}
}

func TestRiverflowSubmitsPollsValidatesReceiptAndDownloadsResult(t *testing.T) {
	resolved, err := Parse([]byte(`{"model":"riverflow/riverflow-2-fast","prompt":"cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	dataURL := "data:image/webp;base64," + testWebP(t, "testdata/riverflow-1024.webp")
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		response := func(status int, value any) (*http.Response, error) {
			body, _ := json.Marshal(value)
			return &http.Response{
				StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header),
			}, nil
		}
		switch requests {
		case 1:
			if req.Method != http.MethodPost || req.URL.String() != "https://design-api.sourceful.com/v2/generations/t2i" {
				t.Fatalf("submit = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("X-API-Key") != "riverflow-key" {
				t.Fatalf("submit headers = %#v", req.Header)
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"model": "riverflow-2-fast", "instruction": "cat",
				"idempotencyKey": "riverflow-one", "resolution": "1K",
			}
			if !reflect.DeepEqual(body, want) {
				t.Fatalf("submit body = %#v, want %#v", body, want)
			}
			return response(201, map[string]any{"data": map[string]any{"jobId": "job-one", "status": "queued"}, "error": nil})
		case 2:
			if req.Method != http.MethodGet || req.URL.String() != "https://design-api.sourceful.com/v2/generations/job-one" {
				t.Fatalf("poll = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("X-API-Key") != "riverflow-key" {
				t.Fatalf("poll headers = %#v", req.Header)
			}
			return response(200, map[string]any{
				"data": map[string]any{
					"job": map[string]any{
						"id": "job-one", "status": "completed",
						"cost": map[string]any{"currency": "USD", "taskCost": 0.02},
					},
					"artifacts": []map[string]any{{"type": "image", "status": "ready", "url": dataURL}},
				},
				"error": nil,
			})
		default:
			t.Fatalf("unexpected request %d: %s", requests, req.URL)
			return nil, nil
		}
	})}
	result, err := NewRegistry(ProviderKeys{Riverflow: "riverflow-key"}, client).Generate(
		t.Context(), resolved, "", "riverflow-one",
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if requests != 2 || len(result.Images) != 1 || result.Images[0].Width != 1024 ||
		result.Images[0].MediaType != "image/webp" {
		t.Fatalf("requests=%d result=%#v", requests, result)
	}
}

func TestRiverflowReceiptUsesExactMicrodollars(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want int
		ok   bool
	}{
		{raw: "0.02", want: 20_000, ok: true},
		{raw: "0.020000", want: 20_000, ok: true},
		{raw: "0.0200001", ok: false},
		{raw: "1e1000000", ok: false},
		{raw: "9999999999999999999999999", ok: false},
		{raw: "0", ok: false},
		{raw: "not-money", ok: false},
	} {
		got, err := exactUSDMicrodollars(json.Number(tt.raw))
		if tt.ok && (err != nil || got != tt.want) {
			t.Fatalf("exactUSDMicrodollars(%q) = %d, %v; want %d", tt.raw, got, err, tt.want)
		}
		if !tt.ok && err == nil {
			t.Fatalf("exactUSDMicrodollars(%q) accepted %d", tt.raw, got)
		}
	}
}

func TestKreaResultURLShapesAndTerminalFailures(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want string
	}{
		{raw: `{"urls":["https://cdn.example/image.png"]}`, want: "https://cdn.example/image.png"},
		{raw: `{"urls":[{"type":"preview","url":"https://cdn.example/preview.png"},{"type":"model","url":"https://cdn.example/model.png"}]}`, want: "https://cdn.example/model.png"},
		{raw: `{"urls":{"preview":"https://cdn.example/preview.png","model":"https://cdn.example/model.png"}}`, want: "https://cdn.example/model.png"},
	} {
		got, err := kreaResultURL(json.RawMessage(tt.raw))
		if err != nil || got != tt.want {
			t.Fatalf("kreaResultURL(%s) = %q, %v; want %q", tt.raw, got, err, tt.want)
		}
	}
	for _, raw := range []string{`null`, `{}`, `{"urls":[]}`, `{"urls":{"model":""}}`} {
		if got, err := kreaResultURL(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted invalid Krea result %s as %q", raw, got)
		}
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
		{
			body:      `{"model":"recraft/recraftv4_1","prompt":"cat"}`,
			generated: GeneratedImage{Width: 2048, Height: 2048}, wantError: true,
		},
		{
			body:      `{"model":"recraft/recraftv4_1","prompt":"cat"}`,
			generated: GeneratedImage{Width: 1024, Height: 1024},
		},
		{
			body:      `{"model":"black-forest-labs/flux-2-klein-4b","prompt":"cat"}`,
			generated: GeneratedImage{Width: 2048, Height: 2048}, wantError: true,
		},
		{
			body:      `{"model":"black-forest-labs/flux-2-klein-4b","prompt":"cat"}`,
			generated: GeneratedImage{Width: 1024, Height: 1024},
		},
		{
			body:      `{"model":"black-forest-labs/flux.1-schnell","prompt":"cat"}`,
			generated: GeneratedImage{Width: 2048, Height: 2048}, wantError: true,
		},
		{
			body:      `{"model":"black-forest-labs/flux.1-schnell","prompt":"cat"}`,
			generated: GeneratedImage{Width: 1024, Height: 1024},
		},
		{
			body:      `{"model":"decart/lucy-image-2","prompt":"edit","resolution":"480p","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,aW1hZ2U="}}]}`,
			generated: GeneratedImage{Width: 720, Height: 720}, wantError: true,
		},
		{
			body:      `{"model":"decart/lucy-image-2","prompt":"edit","resolution":"480p","input_references":[{"type":"image_url","image_url":{"url":"data:image/png;base64,aW1hZ2U="}}]}`,
			generated: GeneratedImage{Width: 480, Height: 480},
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

func testWebP(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func testJPEGBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, nil); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
