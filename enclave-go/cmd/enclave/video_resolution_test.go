package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func TestVideoResolutionTariffDispatchAndSettlement(t *testing.T) {
	for _, tc := range []struct {
		name, model, resolution, echo, primary, wantProvider string
		veniceCandidate, seeded                              bool
	}{
		{name: "2.5 acknowledged", model: "2.5", resolution: "1080p", echo: "1080p", primary: "byteplus", wantProvider: "byteplus"},
		{name: "2.0 acknowledged seeded", model: "2.0", resolution: "1080p", echo: "1080p", primary: "byteplus", wantProvider: "byteplus", seeded: true},
		{name: "missing echo only byteplus", model: "2.5", resolution: "1080p", primary: "byteplus"},
		{name: "wrong echo only byteplus", model: "2.0", resolution: "1080p", echo: "720p", primary: "byteplus"},
		{name: "missing echo authorized venice fallback", model: "2.5", resolution: "1080p", primary: "byteplus", veniceCandidate: true, wantProvider: "venice"},
		{name: "wrong echo authorized venice fallback", model: "2.0", resolution: "1080p", echo: "480p", primary: "byteplus", veniceCandidate: true, wantProvider: "venice"},
		{name: "missing echo byteplus fallback never queues", model: "2.5", resolution: "1080p", primary: "venice", veniceCandidate: true},
		{name: "matching echo permits byteplus fallback", model: "2.0", resolution: "1080p", echo: "1080p", primary: "venice", veniceCandidate: true, wantProvider: "byteplus"},
		{name: "seed cannot fall back to venice", model: "2.5", resolution: "1080p", primary: "byteplus", seeded: true},
		{name: "480p legacy echo absent", model: "2.5", resolution: "480p", primary: "byteplus", wantProvider: "byteplus"},
		{name: "720p legacy echo absent", model: "2.0", resolution: "720p", primary: "byteplus", wantProvider: "byteplus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := "bytedance/seedance-" + tc.model
			endpoint := func(provider string) string { return model + "@" + provider + "/prepaid" }
			limit := map[string]int{"480p": 80_000, "720p": 160_000, "1080p": 400_000}[tc.resolution]
			tokens := map[string]int{"480p": 38_830, "720p": 86_400, "1080p": 194_400}[tc.resolution]
			// The mock control plane owns the tariff snapshot, just as the router does.
			catalogRateTenths := 107
			if tc.model == "2.0" {
				catalogRateTenths = 70
			}
			if tc.echo == "1080p" {
				catalogRateTenths = map[string]int{"2.5": 117, "2.0": 77}[tc.model]
			}
			frozenRateTenths := 0
			byteplusQueues, veniceQueues, prepares, refunds, settles, charged := 0, 0, 0, 0, 0, 0
			held := false
			var stored trustedrouter.VideoJob
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/quote":
					io.WriteString(w, `{"quote":0.40}`)
				case "/contents/generations/tasks":
					byteplusQueues++
					if !held || prepares != 1 {
						t.Error("queued before reservation and storage")
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["resolution"] != tc.resolution {
						t.Errorf("wrong provider resolution: %#v", body)
					}
					io.WriteString(w, `{"id":"cgt-test"}`)
				case "/contents/generations/tasks/cgt-test":
					fmt.Fprintf(w, `{"id":"cgt-test","model":%q,"status":"succeeded","usage":{"completion_tokens":%d},"content":{"video_url":"https://ark-acg-ap-southeast-1.tos-ap-southeast-1.volces.com/a.mp4"}}`, stored.ProviderModel, tokens)
				case "/queue":
					veniceQueues++
					if tc.primary == "venice" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					io.WriteString(w, `{"model":"venice-native","queue_id":"venice-job"}`)
				case "/retrieve":
					w.Header().Set("Content-Type", "video/mp4")
					io.WriteString(w, "video")
				default:
					t.Errorf("unexpected provider request %s", r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer provider.Close()
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				respond := func(data any) {
					if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
						t.Error(err)
					}
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/authorize"):
					if body["video_resolution"] != tc.resolution || body["max_tokens"] != float64(limit) || body["max_output_tokens"] != float64(limit) {
						t.Errorf("invalid authorization: %#v", body)
					}
					policy, _ := body["provider"].(map[string]any)
					if !tc.veniceCandidate && (fmt.Sprint(policy["only"]) != "[byteplus]" || policy["allow_fallbacks"] != false) {
						t.Errorf("routing restriction lost: %#v", policy)
					}
					held, frozenRateTenths = true, catalogRateTenths
					data := map[string]any{"authorization_id": "auth-resolution", "workspace_id": "ws", "api_key_hash": "hash", "model": model, "endpoint_id": endpoint(tc.primary), "provider": tc.primary, "usage_type": "Credits", "video_token_billing": true, "estimated_cost_microdollars": limit * frozenRateTenths / 10}
					if tc.echo != "" {
						data["video_tariff_resolution"] = tc.echo
					}
					if !tc.seeded {
						data["additional_cost_reservation_microdollars"] = 480_000
					}
					if tc.veniceCandidate {
						data["route_candidates"] = []map[string]any{{"provider": "venice", "endpoint_id": endpoint("venice")}, {"provider": "byteplus", "endpoint_id": endpoint("byteplus")}}
					}
					respond(data)
				case strings.HasSuffix(r.URL.Path, "/prepare"):
					prepares++
					if body["provider"] == "byteplus" && (body["quoted_microdollars"] != float64(0) || body["output_token_limit"] != float64(limit)) {
						t.Errorf("invalid token-billed prepare: %v", body)
						w.WriteHeader(400)
						return
					}
					raw, _ := json.Marshal(body)
					if err := json.Unmarshal(raw, &stored); err != nil {
						t.Error(err)
					}
					stored.ID, stored.AuthorizationID, stored.KeyHash, stored.WorkspaceID = "job-resolution", "auth-resolution", "hash", "ws"
					stored.Created, stored.Status = true, "submitting"
					if stored.ProviderJobID != "" {
						t.Error("prepared row already dispatched")
					}
					if tc.wantProvider == "venice" && stored.OutputTokenLimit != 0 {
						t.Error("BytePlus token reservation persisted for Venice")
					}
					respond(stored)
				case strings.HasSuffix(r.URL.Path, "/queued"):
					stored.Provider = body["provider"].(string)
					stored.EndpointID = body["endpoint_id"].(string)
					stored.ProviderModel = body["provider_model"].(string)
					stored.ProviderJobID = body["provider_job_id"].(string)
					stored.QuotedMicrodollars = int(body["quoted_microdollars"].(float64))
					stored.Status = "pending"
					respond(stored)
				case strings.HasSuffix(r.URL.Path, "/refund"):
					refunds++
					held = false
					wantError := "video_tariff_unavailable"
					if tc.primary == "venice" {
						wantError = "video_provider_error"
					}
					if body["authorization_id"] != "auth-resolution" || body["error_type"] != wantError {
						t.Error("refunded wrong hold")
					}
					respond(map[string]any{"settled": true})
				case strings.HasSuffix(r.URL.Path, "/settle"):
					settles++
					held = false
					if body["authorization_id"] != stored.AuthorizationID || body["selected_endpoint"] != endpoint(tc.wantProvider) || body["video_resolution"] != tc.resolution {
						t.Errorf("wrong settlement identity: %#v", body)
					}
					if tc.wantProvider == "byteplus" {
						if body["actual_output_tokens"] != float64(tokens) || body["actual_input_tokens"] != float64(0) || body["additional_cost_microdollars"] != nil {
							t.Errorf("wrong token settlement: %#v", body)
						}
						charged = tokens * frozenRateTenths / 10
					} else {
						if body["actual_output_tokens"] != float64(0) || body["additional_cost_microdollars"] != float64(480_000) {
							t.Errorf("Venice charged BytePlus usage: %#v", body)
						}
						charged = 480_000
					}
					respond(map[string]any{"generation_id": "gen-resolution", "cost_microdollars": charged})
				case strings.HasSuffix(r.URL.Path, "/update"):
					stored.Status = body["status"].(string)
					if stored.Status == "completed" {
						stored.SettledMicrodollars = &charged
						if tc.wantProvider == "byteplus" {
							stored.OutputTokens = &tokens
						}
					}
					respond(stored)
				default:
					t.Errorf("unexpected control request %s", r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer control.Close()
			s := &videoService{providers: video.NewRegistryWithProviders(video.NewBytePlusClientAt("key", provider.URL, provider.Client()), video.NewVeniceClientAt("key", provider.URL, provider.Client())), control: trustedrouter.New(control.URL, "internal", control.Client())}
			policy := map[string]any{"only": []string{"byteplus"}, "allow_fallbacks": false}
			if tc.veniceCandidate {
				policy = map[string]any{"only": []string{"byteplus", "venice"}, "allow_fallbacks": true}
			}
			request := map[string]any{"model": model, "prompt": "private", "duration": 4, "resolution": tc.resolution, "provider": policy}
			if tc.seeded {
				request["seed"] = 1101
			}
			raw, _ := json.Marshal(request)
			var out bytes.Buffer
			s.serveCreate(t.Context(), &out, raw, "key", "idem")
			if tc.wantProvider == "" {
				if strings.Contains(out.String(), "202 Accepted") || byteplusQueues != 0 || refunds != 1 || settles != 0 || charged != 0 || held {
					t.Fatalf("unsafe rejection: response=%s queues=%d refunds=%d settles=%d charged=%d held=%t", out.String(), byteplusQueues, refunds, settles, charged, held)
				}
				if tc.primary == "byteplus" && (prepares != 1 || stored.ProviderJobID != "" || stored.Status != "failed" || !strings.Contains(out.String(), "video_tariff_unavailable")) {
					t.Fatalf("missing durable tariff rejection: job=%+v response=%s", stored, out.String())
				}
				return
			}
			if !strings.Contains(out.String(), "202 Accepted") || stored.Provider != tc.wantProvider {
				t.Fatalf("wrong dispatch: job=%+v response=%s", stored, out.String())
			}
			if (tc.wantProvider == "byteplus" && byteplusQueues != 1) || (tc.wantProvider == "venice" && (byteplusQueues != 0 || veniceQueues != 1)) {
				t.Fatalf("queues: byteplus=%d venice=%d", byteplusQueues, veniceQueues)
			}
			// A later catalog refresh must not affect the mock's authorization snapshot.
			catalogRateTenths = 1
			updated, err := s.pollAndFinalize(t.Context(), &stored, "")
			if err != nil {
				t.Fatal(err)
			}
			if updated.Status != "completed" || settles != 1 || refunds != 0 || held {
				t.Fatalf("incomplete settlement: %+v settles=%d refunds=%d held=%t", updated, settles, refunds, held)
			}
			wantCost := 480_000
			if tc.wantProvider == "byteplus" {
				wantCost = tokens * frozenRateTenths / 10
			}
			out.Reset()
			writeVideoJobResponse(&out, 200, updated)
			usage := videoHTTPBody(t, out.String())["usage"].(map[string]any)
			if usage["cost_microdollars"] != float64(wantCost) {
				t.Fatalf("wrong public cost: %#v, want %d", usage, wantCost)
			}
		})
	}
}
