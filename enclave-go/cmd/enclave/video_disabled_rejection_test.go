package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func TestVideoDisabledRejectionRefundRestart(t *testing.T) {
	for _, tc := range []struct {
		name, wantProvider, wantEndpoint  string
		candidate, missingPrimaryEndpoint bool
	}{
		{name: "disabled_primary", wantProvider: "venice", wantEndpoint: "primary"},
		{name: "disabled_primary_and_candidate_keep_primary", candidate: true, wantProvider: "venice", wantEndpoint: "primary"},
		{name: "disabled_primary_and_candidate_use_candidate", candidate: true, missingPrimaryEndpoint: true, wantProvider: "byteplus", wantEndpoint: "fallback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newRefundAuthority(t)
			a.failRefund = true
			a.customizeAuth = func(auth map[string]any) {
				if tc.candidate {
					auth["route_candidates"] = []map[string]any{{"provider": "byteplus", "endpoint_id": "fallback"}}
				}
				if tc.missingPrimaryEndpoint {
					// An incomplete primary cannot name a row. The disabled
					// token candidate can retain the authorized bound instead.
					auth["endpoint_id"] = ""
				}
			}
			newService := func(endpoints string) (*videoService, []*refundTestProvider) {
				google := &refundTestProvider{Provider: video.NewGoogleVeoClient("test", nil)}
				venice := &refundTestProvider{Provider: video.NewVeniceClient("", nil)}
				bp := video.NewBytePlusClient("", nil)
				byteplus := &refundTestProvider{Provider: bp}
				return &videoService{
					control: trustedrouter.New(endpoints, "internal", &http.Client{Transport: a}),
					providers: video.NewRegistryWithProviders(google, venice,
						&tariffTestProvider{refundTestProvider: byteplus, TokenBilledProvider: bp}),
					workerID: "worker",
				}, []*refundTestProvider{google, venice, byteplus}
			}
			s, spies := newService("http://127.0.0.1:18082,http://127.0.0.1:18081")
			create := func(service *videoService) string {
				var out bytes.Buffer
				service.serveCreate(t.Context(), &out, []byte(`{"model":"google/veo-3.1","prompt":"cube","resolution":"720p","duration":4,"seed":1101}`), "test", "disabled")
				return out.String()
			}
			out := create(s)
			if !strings.HasPrefix(out, "HTTP/1.1 503 ") || !strings.Contains(out, `"code":"video_routing_unavailable"`) {
				t.Fatal(out)
			}
			jobID := trustedrouter.VideoJobID("auth-disabled")
			job := a.jobs[jobID]
			wantQuote, wantLimit := 500000, 0
			if tc.missingPrimaryEndpoint {
				wantQuote, wantLimit = 0, a.authorizedLimits["auth-disabled"]
			}
			if a.prepares != 1 || len(a.jobs) != 1 || job.Provider != tc.wantProvider || job.EndpointID != tc.wantEndpoint || job.QuotedMicrodollars != wantQuote || job.OutputTokenLimit != wantLimit || job.Status != "submitting" || job.ProviderJobID != "" || !a.held["auth-disabled"] || a.releases != 0 || len(a.refunds) != 1 {
				t.Errorf("missing durable rejection: prepares=%d jobs=%d held=%v row=%+v refunds=%v", a.prepares, len(a.jobs), a.held, job, a.refunds)
			}
			// Only the authority's store survives; every client and adapter is new.
			// Reversed endpoint order requires claims to restore the authority pin.
			fresh, freshSpies := newService("http://127.0.0.1:18081,http://127.0.0.1:18082")
			a.failRefund = false
			if n, err := fresh.drain(t.Context()); n != 0 || err != nil {
				t.Fatalf("claimed before due: %d %v", n, err)
			}
			a.now = a.now.Add(600 * time.Second)
			if n, err := fresh.drain(t.Context()); n != 1 || err != nil {
				t.Errorf("restart drain: claimed=%d err=%v held=%v", n, err, a.held)
			}
			if a.jobs[jobID].Status != "failed" || a.held["auth-disabled"] || a.releases != 1 || len(a.refunds) != 2 {
				t.Errorf("refund lost or duplicated: row=%+v held=%v releases=%d refunds=%v", a.jobs[jobID], a.held, a.releases, a.refunds)
			}
			if len(a.refunds) == 2 && (a.refunds[1]["authorization_id"] != "auth-disabled" || a.refunds[1]["error_type"] != "video_submission_interrupted") {
				t.Errorf("wrong recovery refund: %v", a.refunds)
			}
			a.now = a.now.Add(600 * time.Second)
			if n, err := fresh.drain(t.Context()); n != 0 || err != nil || a.releases != 1 || len(a.refunds) != 2 || a.prepares != 1 || len(a.jobs) != 1 || a.newHolds != 1 {
				t.Errorf("repeated drain changed obligation: claimed=%d err=%v prepares=%d releases=%d", n, err, a.prepares, a.releases)
			}
			for _, spy := range append(spies, freshSpies...) {
				if spy.queues != 0 || spy.polls != 0 {
					t.Errorf("rejection accessed provider %s: queues=%d polls=%d", spy.ID(), spy.queues, spy.polls)
				}
			}
		})
	}
}

func TestVideoDisabledProviderNeverDispatched(t *testing.T) {
	venice := &refundTestProvider{Provider: video.NewVeniceClient("", nil)}
	google := &refundTestProvider{Provider: video.NewGoogleVeoClient("test", nil)}
	s := &videoService{providers: video.NewRegistryWithProviders(venice, google)}
	request, err := video.ResolveRequest(&video.CreateRequest{Model: "google/veo-3.1", Prompt: "cube", Resolution: "720p", Duration: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !venice.Supports(request) {
		t.Fatal("disabled adapter must otherwise support the request")
	}
	providers := s.providers.Supporting(request)
	if len(providers) != 1 || providers[0].ID() != google.ID() {
		t.Fatalf("disabled adapter admitted to quoting: %v", providers)
	}
	if _, ok := s.providers.Provider("venice"); ok {
		t.Fatal("dispatch lookup admitted disabled adapter")
	}
	// Supply an otherwise admissible route directly to exercise the final
	// dispatch guard independently of Supporting and quote selection.
	routes := []authorizedVideoRoute{{Provider: "venice", EndpointID: "primary"}}
	if _, queued, err := s.queueVideoJob(t.Context(), request, routes); err == nil || queued != nil || venice.queues != 0 {
		t.Fatalf("disabled primary dispatched: queued=%v err=%v queues=%d", queued, err, venice.queues)
	}
	routes = append(routes, authorizedVideoRoute{Provider: google.ID(), EndpointID: "fallback"})
	selected, queued, err := s.queueVideoJob(t.Context(), request, routes)
	if err != nil || queued == nil || selected.Provider != google.ID() || google.queues != 1 || venice.queues != 0 {
		t.Fatalf("disabled primary affected fallback: selected=%+v queued=%v err=%v", selected, queued, err)
	}
}
