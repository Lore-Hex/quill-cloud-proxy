package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

// Exercise the real authorization decoder, not a mock that skips nonce checks.
func TestVideoCreateReplayOnlyLooksUpTheOriginalJob(t *testing.T) {
	for _, state := range []string{"submitting", "pending", "in_progress", "completed", "failed"} {
		t.Run(state, func(t *testing.T) {
			jobID := trustedrouter.VideoJobID("auth-original")
			providerCalls, authorizes, lookups, mutations := 0, 0, 0, 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls++
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer provider.Close()
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authorizes++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["idempotency_key"] != "original-key" || body["request_fingerprint"] == "" || body["invocation_nonce"] == "original-nonce" {
						t.Errorf("invalid replay authorization: %#v", body)
					}
					// No routes or pricing: a recovered authorization grants no dispatch rights.
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"authorization_id": "auth-original", "workspace_id": "ws", "api_key_hash": "hash",
						"model": "bytedance/seedance-2.5", "idempotent_replay": true, "invocation_nonce": "original-nonce",
					}})
				case "/internal/gateway/video/jobs/" + jobID + "/lookup":
					lookups++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["api_key_lookup_hash"] != trustedrouter.LookupHash("test") {
						t.Error("lookup did not authenticate the caller")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"id": jobID, "authorization_id": "auth-original", "workspace_id": "ws", "key_hash": "hash",
						"model": "bytedance/seedance-2.5", "provider": "byteplus", "status": state,
						"settled_microdollars": 438332, "output_tokens": 38830, "created": true,
					}})
				default:
					mutations++
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer control.Close()
			s := &videoService{
				providers: video.NewRegistryWithProviders(video.NewBytePlusClientAt("test", provider.URL, provider.Client())),
				control:   trustedrouter.New(control.URL, "internal", control.Client()),
			}
			for range 2 {
				var out bytes.Buffer
				s.serveCreate(context.Background(), &out, []byte(`{"model":"bytedance/seedance-2.5","prompt":"private prompt","duration":4,"resolution":"480p","provider":{"only":["byteplus"]}}`), "test", "original-key")
				if !strings.HasPrefix(out.String(), "HTTP/1.1 202") {
					t.Fatalf("replay failed: %s", out.String())
				}
				body := videoHTTPBody(t, out.String())
				publicState := state
				if publicState == "submitting" {
					publicState = "pending"
				}
				if body["id"] != jobID || body["status"] != publicState {
					t.Fatalf("wrong replay: %#v", body)
				}
			}
			if authorizes != 2 || lookups != 2 || mutations != 0 || providerCalls != 0 {
				t.Fatalf("authorize=%d lookup=%d mutations=%d provider=%d", authorizes, lookups, mutations, providerCalls)
			}
		})
	}
}
