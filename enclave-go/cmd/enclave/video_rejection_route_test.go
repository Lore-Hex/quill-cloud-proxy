package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

// Exercise rejection storage independently of dispatch admission: an authorized
// candidate usable for this row might also be dispatchable on a newer router.
func TestVideoRejectionAuthorizedRow(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		tariff                     bool
		primary                    string
		cost, limit                int
		candidates                 []map[string]any
		wantProvider, wantEndpoint string
		wantQuote, wantLimit       int
	}{
		{name: "routing_zero_fixed_quote_uses_token_candidate", primary: "venice", limit: 400000,
			candidates:   []map[string]any{{"provider": "venice", "endpoint_id": "fixed-candidate"}, {"provider": "byteplus", "endpoint_id": "token-candidate"}, {"provider": "byteplus", "endpoint_id": "later-token"}},
			wantProvider: "byteplus", wantEndpoint: "token-candidate", wantLimit: 400000},
		{name: "routing_zero_fixed_quote_without_candidate", primary: "venice", limit: 400000},
		{name: "tariff_positive_fixed_primary", tariff: true, primary: "venice", cost: 123456, limit: 400000,
			candidates:   []map[string]any{{"provider": "byteplus", "endpoint_id": "token-candidate"}},
			wantProvider: "venice", wantEndpoint: "primary", wantQuote: 123456},
		{name: "tariff_zero_fixed_quote_uses_token_candidate", tariff: true, primary: "venice", limit: 400000,
			candidates:   []map[string]any{{"provider": "byteplus", "endpoint_id": "token-candidate"}},
			wantProvider: "byteplus", wantEndpoint: "token-candidate", wantLimit: 400000},
		{name: "routing_token_primary_uses_authorized_minimum", primary: "byteplus", cost: 123456,
			wantProvider: "byteplus", wantEndpoint: "primary", wantLimit: 1},
		{name: "tariff_zero_fixed_quote_without_candidate", tariff: true, primary: "venice", limit: 400000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newRefundAuthority(t)
			a.failRefund = true
			a.customizeAuth = func(auth map[string]any) {
				auth["provider"] = tc.primary
				auth["video_token_billing"], auth["estimated_cost_microdollars"] = true, 1
				auth["additional_cost_reservation_microdollars"] = tc.cost
				auth["route_candidates"] = tc.candidates
			}
			client := trustedrouter.New("http://127.0.0.1:18082,http://127.0.0.1:18081", "internal", &http.Client{Transport: a})
			s, bp := tariffService(client)
			venice := &refundTestProvider{Provider: video.NewVeniceClient("test", nil)}
			tokenProvider, _ := s.providers.Provider("byteplus")
			s.providers = video.NewRegistryWithProviders(tokenProvider, venice)
			quotes := map[string]videoQuote{"byteplus": {OutputTokenLimit: tc.limit, Microdollars: tc.cost}}
			limit := maximumVideoTokenLimit(quotes)
			ctx := trustedrouter.WithVideoAllowedProviders(t.Context(), []string{"byteplus"})
			auth, _, err := client.AuthorizeVideo(ctx, "test", "bytedance/seedance-2.5", "720p", "row", strings.Repeat("a", 64), map[string]any{"allow_fallbacks": false}, tc.cost, limit)
			if err != nil {
				t.Fatal(err)
			}
			job := &trustedrouter.VideoJob{ID: trustedrouter.VideoJobID(auth.AuthorizationID), AuthorizationID: auth.AuthorizationID,
				Model: auth.Model, ProviderModel: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID,
				QuotedMicrodollars: auth.AdditionalCostReservationMicrodollars, OutputTokenLimit: max(1, limit),
				ControlPlaneEndpoint: auth.ControlPlaneEndpoint, ControlPlaneEndpointSet: auth.ControlPlaneEndpointSet}
			var out bytes.Buffer
			s.rejectVideoAuthorization(t.Context(), &out, auth, job, tc.tariff)
			reason := "video_routing_unavailable"
			if tc.tariff {
				reason = "video_tariff_unavailable"
			}
			if !strings.HasPrefix(out.String(), "HTTP/1.1 503 ") || videoHTTPBody(t, out.String())["error"].(map[string]any)["code"] != reason || len(a.refunds) != 1 || a.refunds[0]["error_type"] != reason {
				t.Fatalf("rejection=%s refunds=%v", out.String(), a.refunds)
			}
			if bp.queues+venice.queues != 0 {
				t.Fatal("rejected row dispatched")
			}
			if tc.wantProvider == "" {
				if a.prepares != 0 || len(a.jobs) != 0 {
					t.Fatalf("unrepresentable row attempted: prepares=%d jobs=%v", a.prepares, a.jobs)
				}
				return
			}
			stored := a.jobs[job.ID]
			if a.prepares != 1 || stored.Provider != tc.wantProvider || stored.EndpointID != tc.wantEndpoint || stored.QuotedMicrodollars != tc.wantQuote || stored.OutputTokenLimit != tc.wantLimit || stored.Status != "submitting" || stored.ProviderJobID != "" || !a.held[auth.AuthorizationID] {
				t.Fatalf("invalid durable row: %+v", stored)
			}
		})
	}
}

func TestVideoSeedTokenOnlyQuoteNoValidRejectionRow(t *testing.T) {
	a := newRefundAuthority(t)
	a.customizeAuth = func(auth map[string]any) {
		auth["additional_cost_reservation_microdollars"] = 0
		auth["video_token_billing"], auth["estimated_cost_microdollars"] = true, 1
	}
	client := trustedrouter.New("http://127.0.0.1:18082", "internal", &http.Client{Transport: a})
	s, bp := tariffService(client)
	tokenProvider, _ := s.providers.Provider("byteplus")
	venice := &refundTestProvider{Provider: video.NewVeniceClient("test", nil)}
	s.providers = video.NewRegistryWithProviders(tokenProvider, venice)
	var out bytes.Buffer
	s.serveCreate(t.Context(), &out, []byte(`{"model":"bytedance/seedance-2.5","prompt":"cube","resolution":"720p","duration":4,"seed":1101,"provider":{"allow_fallbacks":false}}`), "test", "seed-only")
	if !strings.HasPrefix(out.String(), "HTTP/1.1 503 ") || videoHTTPBody(t, out.String())["error"].(map[string]any)["code"] != "video_routing_unavailable" || a.prepares != 0 || len(a.jobs) != 0 || a.releases != 1 || len(a.refunds) != 1 || a.refunds[0]["error_type"] != "video_routing_unavailable" || bp.queues+venice.queues != 0 {
		t.Fatalf("response=%s prepares=%d jobs=%v refunds=%v", out.String(), a.prepares, a.jobs, a.refunds)
	}
}

func TestVideoRejectionPrepareErrorClassification(t *testing.T) {
	for _, tariff := range []bool{false, true} {
		for _, status := range []int{400, 503, 0} {
			t.Run(fmt.Sprintf("tariff=%t/status=%d", tariff, status), func(t *testing.T) {
				a := newRefundAuthority(t)
				a.prepareStatus, a.prepareTransportFailure = status, status == 0
				a.tariff = tariff
				var out string
				var queues int
				if tariff {
					client := trustedrouter.New("http://127.0.0.1:18082", "internal", &http.Client{Transport: a})
					s, bp := tariffService(client)
					out = tariffCreate(t, s, true)
					queues = bp.queues
				} else {
					s, fal, venice := a.service()
					out = refundCreate(t, s, "error", true)
					queues = fal.queues + venice.queues
				}
				code := "video_job_store_unavailable"
				if status == 400 {
					code = "video_routing_unavailable"
					if tariff {
						code = "video_tariff_unavailable"
					}
				}
				if !strings.HasPrefix(out, "HTTP/1.1 503 ") || videoHTTPBody(t, out)["error"].(map[string]any)["code"] != code || len(a.jobs) != 0 || len(a.refunds) != 1 || a.refunds[0]["error_type"] != code || a.releases != 1 || queues != 0 || a.prepares == 0 {
					t.Fatalf("response=%s prepares=%d refunds=%v", out, a.prepares, a.refunds)
				}
			})
		}
	}
}

func TestVideoTariffFixedPrimaryQuote(t *testing.T) {
	a := newRefundAuthority(t)
	a.customizeAuth = func(auth map[string]any) {
		auth["additional_cost_reservation_microdollars"] = 123456
		auth["route_candidates"] = []map[string]any{{"provider": "byteplus", "endpoint_id": "token-candidate"}}
	}
	client := trustedrouter.New("http://127.0.0.1:18082", "internal", &http.Client{Transport: a})
	s, bp := tariffService(client)
	tokenProvider, _ := s.providers.Provider("byteplus")
	venice := &refundTestProvider{Provider: video.NewVeniceClient("test", nil)}
	s.providers = video.NewRegistryWithProviders(tokenProvider, venice)
	out := tariffCreate(t, s, true)
	job := a.jobs[trustedrouter.VideoJobID("auth-tariff")]
	if !strings.HasPrefix(out, "HTTP/1.1 503 ") || videoHTTPBody(t, out)["error"].(map[string]any)["code"] != "video_tariff_unavailable" || a.prepares != 1 || job.Provider != "venice" || job.EndpointID != "primary" || job.QuotedMicrodollars != 123456 || job.OutputTokenLimit != 0 || job.Status != "failed" || job.LastError != "tariff_unavailable" || a.releases != 1 || bp.queues+venice.queues != 0 {
		t.Fatalf("response=%s row=%+v refunds=%v", out, job, a.refunds)
	}
}
