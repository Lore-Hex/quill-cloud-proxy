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

// The test router retains the pre-rollout fingerprint rules: headers do not
// participate; the entire body does (except nonce, credentials and live quote).
// Authorize through the old path, then retry through seeded serveCreate.
func TestVideoSeedReplayAcrossRoutingConstraintRollout(t *testing.T) {
	for _, policy := range []string{"", `,"provider":{"order":["fal"],"allow_fallbacks":false}`} {
		t.Run(policy, func(t *testing.T) {
			const model = "minimax/h3-max"
			request := []byte(`{"model":"minimax/h3-max","prompt":"original","seed":1101}`)
			request = []byte(strings.TrimSuffix(string(request), "}") + policy + "}")
			var req video.CreateRequest
			if err := json.Unmarshal(request, &req); err != nil {
				t.Fatal(err)
			}
			var originalBody []byte
			authorizes, lookups, mutations := 0, 0, 0
			jobID := trustedrouter.VideoJobID("before-rollout")
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authorizes++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					for _, key := range []string{"invocation_nonce", "api_key_lookup_hash", "idempotency_key", "additional_cost_reservation_microdollars"} {
						delete(body, key)
					}
					material, err := json.Marshal(body)
					if err != nil {
						t.Error(err)
					}
					replay := originalBody != nil
					if !replay {
						if r.Header.Get("X-Quill-Video-Allowed-Providers") != "" {
							t.Error("pre-rollout authorization had derived routing")
						}
						originalBody = material
					} else if !bytes.Equal(originalBody, material) {
						http.Error(w, `{"error":{"message":"Idempotency key was already used for a different gateway request"}}`, 409)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"authorization_id": "before-rollout", "workspace_id": "ws", "api_key_hash": "hash", "model": model,
						"provider": "fal", "endpoint_id": model + "@fal/prepaid", "idempotent_replay": replay,
						"additional_cost_reservation_microdollars": 500000,
					}})
				case "/internal/gateway/video/jobs/" + jobID + "/lookup":
					lookups++
					if r.Header.Get("X-Quill-Video-Allowed-Providers") != "" {
						t.Error("derived routing leaked into job lookup")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"id": jobID, "authorization_id": "before-rollout", "workspace_id": "ws", "key_hash": "hash",
						"model": model, "provider": "fal", "status": "completed",
					}})
				default:
					mutations++
					http.Error(w, "unexpected mutation", 500)
				}
			}))
			defer control.Close()
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("replay dispatched provider work")
				w.WriteHeader(500)
			}))
			defer provider.Close()
			client := trustedrouter.New(control.URL, "test", control.Client())
			auth, job, err := client.AuthorizeVideo(t.Context(), "test", model, "original-key", videoRequestFingerprint("test", &req), req.Provider, 500000, 0)
			if err != nil || auth == nil || job != nil {
				t.Fatalf("pre-rollout authorize: auth=%+v job=%+v err=%v", auth, job, err)
			}
			s := &videoService{control: client, providers: video.NewRegistryWithProviders(video.NewFALVideoClientAt("test", provider.URL, provider.Client()))}
			for _, tc := range []struct {
				body   []byte
				status string
			}{
				{request, "202"},
				{bytes.Replace(request, []byte(`"original"`), []byte(`"changed"`), 1), "409"},
				{bytes.Replace(request, []byte(`1101`), []byte(`1102`), 1), "409"},
				{[]byte(`{"model":"minimax/h3-max","prompt":"original","seed":1101,"provider":{"only":["fal"]}}`), "409"},
				{request, "202"},
			} {
				var out bytes.Buffer
				s.serveCreate(t.Context(), &out, tc.body, "test", "original-key")
				if !strings.HasPrefix(out.String(), "HTTP/1.1 "+tc.status) {
					t.Fatalf("replay response=%s, want %s", out.String(), tc.status)
				}
				if tc.status == "202" && videoHTTPBody(t, out.String())["id"] != jobID {
					t.Fatalf("wrong recovered job: %s", out.String())
				}
			}
			if authorizes != 6 || lookups != 2 || mutations != 0 {
				t.Fatalf("authorize=%d lookups=%d mutations=%d", authorizes, lookups, mutations)
			}
		})
	}
}
