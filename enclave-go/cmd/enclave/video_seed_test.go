package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func TestVideoSeedRejectedBeforeQuoteOrAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, model, policy, extra, routes string
		byteplus                           bool
	}{
		{"venice_only", "bytedance/seedance-2.5", `"provider":{"only":["venice"]},`, "", "venice", true},
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
				if calls.Load() != 0 {
					t.Fatalf("made %d provider/billing calls", calls.Load())
				}
			})
		}
	}
}
