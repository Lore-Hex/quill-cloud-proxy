package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

type videoQuoteSpy struct {
	video.Provider
	quotes atomic.Int32
}

// Preserve token billing when instrumenting a provider's quote method.
type videoTokenQuoteSpy struct {
	*videoQuoteSpy
	video.TokenBilledProvider
}

func (s *videoQuoteSpy) QuoteResolved(ctx context.Context, req *video.ResolvedRequest) (int, error) {
	s.quotes.Add(1)
	return s.Provider.QuoteResolved(ctx, req)
}

func TestVideoSeedRejectedBeforeQuoteOrAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, model, policy, extra, routes string
		byteplus                           bool
	}{
		{"venice_only", "bytedance/seedance-2.5", `"provider":{"only":["venice"]},`, "", "venice", true},
		{"venice_order_no_fallbacks", "bytedance/seedance-2.5", `"provider":{"order":["venice"],"allow_fallbacks":false},`, "", "venice", true},
		{"disjoint_only_order", "bytedance/seedance-2.5", `"provider":{"only":["byteplus"],"order":["venice"],"allow_fallbacks":false},`, "", "none enabled", true},
		{"google_ignored", "google/veo-3.1", `"provider":{"ignore":["google"]},`, "", "venice", false},
		{"google_alias_ignored", "google/veo-3.1", `"provider":{"ignore":[" AI_Studio "]},`, "", "venice", false},
		{"google_order_ignored", "google/veo-3.1", `"provider":{"order":["gemini"],"ignore":["google"],"allow_fallbacks":false},`, "", "none enabled", false},
		{"google_order_other_domain", "google/veo-3.1", `"provider":{"order":["vertex"],"allow_fallbacks":false},`, "", "none enabled", false},
		{"venice_string", "bytedance/seedance-2.5", `"provider":{"only":"Venice"},`, "", "venice", true},
		{"byteplus_ignored", "bytedance/seedance-2.5", `"provider":{"ignore":["byteplus"]},`, "", "venice", true},
		{"byteplus_disabled", "bytedance/seedance-2.5", "", "", "venice", false},
		{"venice_model", "google/gemini-omni-flash", "", "", "venice", true},
		{"byteplus_incompatible_resolution", "bytedance/seedance-2.5", "", `"resolution":"1080p",`, "venice", true},
	} {
		for _, seed := range []int64{0, 1101} {
			t.Run(fmt.Sprintf("%s/seed=%d", tc.name, seed), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					t.Errorf("unexpected provider or control-plane call: %s", r.URL.Path)
					http.Error(w, "unexpected request", 500)
				}))
				defer server.Close()
				providers := []video.Provider{video.NewVeniceClientAt("test", server.URL, server.Client())}
				if tc.byteplus {
					providers = append(providers, video.NewBytePlusClientAt("test", server.URL, server.Client()))
				}
				if tc.model == "google/veo-3.1" {
					providers = append(providers, video.NewGoogleVeoClient("test", server.Client()))
				}
				spies := make([]*videoQuoteSpy, len(providers))
				for i, provider := range providers {
					spies[i] = &videoQuoteSpy{Provider: provider}
					providers[i] = spies[i]
					if tokenProvider, ok := provider.(video.TokenBilledProvider); ok {
						providers[i] = &videoTokenQuoteSpy{videoQuoteSpy: spies[i], TokenBilledProvider: tokenProvider}
					}
				}
				s := &videoService{providers: video.NewRegistryWithProviders(providers...), control: trustedrouter.New(server.URL, "test", server.Client())}
				body := fmt.Sprintf(`{"model":%q,"prompt":"A blue cube",%s%s"seed":%d}`, tc.model, tc.policy, tc.extra, seed)
				var out bytes.Buffer
				s.serveCreate(context.Background(), &out, []byte(body), "test", "idem")
				if !strings.HasPrefix(out.String(), "HTTP/1.1 400 ") {
					t.Fatalf("response = %s", out.String())
				}
				failure := videoHTTPBody(t, out.String())["error"].(map[string]any)
				wantMessage := fmt.Sprintf("seed is not supported for model %q on the allowed video routes (%s)", tc.model, tc.routes)
				if failure["message"] != wantMessage || failure["type"] != "invalid_request_error" || failure["code"] != "unsupported_parameter" || failure["param"] != "seed" || failure["source"] != "router" {
					t.Fatalf("error = %#v", failure)
				}
				for _, spy := range spies {
					if spy.quotes.Load() != 0 {
						t.Errorf("quoted excluded provider %s %d times", spy.ID(), spy.quotes.Load())
					}
				}
				if calls.Load() != 0 {
					t.Fatalf("made %d provider/billing calls", calls.Load())
				}
			})
		}
	}
}

func TestVideoSeedProviderAliasesReachAuthorization(t *testing.T) {
	for _, policy := range []string{
		`{"only":["google"]}`, `{"only":["ai-studio"]}`,
		`{"only":" Google_AI , vertex "}`, `{"only":["gemini"]}`,
		`{"order":["AI Studio"],"allow_fallbacks":false}`,
		`{"only":["google"],"order":["google_ai_studio"],"allow_fallbacks":false}`,
		`{"order":["venice"],"allow_fallbacks":true}`,
		`{"order":["venice"]}`, `{"order":[],"allow_fallbacks":false}`,
		`{"only":[],"ignore":[],"allow_fallbacks":false}`,
		`{"only":["google"],"ignore":["vertex-ai"]}`,
	} {
		t.Run(policy, func(t *testing.T) {
			var calls atomic.Int32
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/internal/gateway/authorize" || r.Header.Get("X-Quill-Video-Allowed-Providers") != "google-ai-studio" {
					t.Errorf("incorrect authorization constraint: %s %v", r.URL.Path, r.Header)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["request_fingerprint"] == "" {
					t.Error("missing logical identity")
				}
				http.Error(w, `{"error":{"message":"test authorization denied"}}`, http.StatusForbidden)
			}))
			defer control.Close()
			google := &videoQuoteSpy{Provider: video.NewGoogleVeoClient("test", control.Client())}
			venice := &videoQuoteSpy{Provider: video.NewVeniceClientAt("test", control.URL, control.Client())}
			s := &videoService{providers: video.NewRegistryWithProviders(google, venice), control: trustedrouter.New(control.URL, "test", control.Client())}
			var out bytes.Buffer
			s.serveCreate(t.Context(), &out, []byte(`{"model":"google/veo-3.1","prompt":"cube","seed":0,"provider":`+policy+`}`), "test", "idem")
			if !strings.HasPrefix(out.String(), "HTTP/1.1 403 ") || calls.Load() != 1 || google.quotes.Load() != 1 || venice.quotes.Load() != 0 {
				t.Fatalf("response=%s calls=%d google quotes=%d venice quotes=%d", out.String(), calls.Load(), google.quotes.Load(), venice.quotes.Load())
			}
		})
	}
}
