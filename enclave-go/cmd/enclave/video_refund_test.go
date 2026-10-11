package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

// Only the authority owns jobs, holds and leases. Rebuilding service/client
// objects shares this fake external store, never enclave-side refund state.
type refundAuthority struct {
	t                                                                                    *testing.T
	now                                                                                  time.Time
	jobs                                                                                 map[string]trustedrouter.VideoJob
	due, lease                                                                           map[string]time.Time
	authorizations                                                                       map[string]string
	held                                                                                 map[string]bool
	order                                                                                []string
	calls                                                                                []string
	refunds                                                                              []map[string]any
	newHolds, releases, prepares, lookups, settlements                                   int
	failRefund, hangRefund, failPrepare, failUpdate, existingPrepare, compatibleFallback bool
	refundBudget                                                                         time.Duration
	tariff                                                                               bool
	authorizationRows                                                                    map[string]map[string]any
	authorizedLimits                                                                     map[string]int
	customizeAuth                                                                        func(map[string]any)
	prepareStatus                                                                        int
	prepareTransportFailure                                                              bool
}

func newRefundAuthority(t *testing.T) *refundAuthority {
	return &refundAuthority{t: t, now: time.Now(), jobs: map[string]trustedrouter.VideoJob{}, due: map[string]time.Time{}, lease: map[string]time.Time{}, authorizations: map[string]string{}, authorizationRows: map[string]map[string]any{}, authorizedLimits: map[string]int{}, held: map[string]bool{}}
}

func (a *refundAuthority) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	reply := func(status int, data any) (*http.Response, error) {
		body, err := json.Marshal(map[string]any{"data": data})
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, err
	}
	if r.URL.Host == "127.0.0.1:18081" {
		if strings.HasSuffix(r.URL.Path, "/claim") {
			return reply(200, []trustedrouter.VideoJob{})
		}
		a.t.Errorf("crossed pinned authority: %s", r.URL)
		return reply(500, nil)
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.t.Fatal(err)
	}
	a.calls = append(a.calls, r.URL.Path)
	if !strings.HasSuffix(r.URL.Path, "/authorize") && r.Header.Get("X-Quill-Video-Allowed-Providers") != "" {
		a.t.Error("routing header leaked")
	}
	switch r.URL.Path {
	case "/internal/gateway/authorize":
		key := body["idempotency_key"].(string)
		id, replay := a.authorizations[key]
		if !replay {
			id = "auth-" + key
			a.authorizations[key] = id
			a.held[id] = true
			a.newHolds++
		}
		auth := map[string]any{"authorization_id": id, "workspace_id": "ws", "api_key_hash": "hash", "model": body["model"], "provider": "venice", "endpoint_id": "primary", "additional_cost_reservation_microdollars": 500000, "idempotent_replay": replay}
		if a.tariff {
			auth["model"], auth["provider"] = body["model"], "byteplus"
			auth["video_token_billing"] = true
		}
		if a.compatibleFallback {
			auth["route_candidates"] = []map[string]any{{"provider": "fal", "endpoint_id": "fallback"}}
		}
		if a.customizeAuth != nil {
			a.customizeAuth(auth)
		}
		a.authorizationRows[id] = auth
		a.authorizedLimits[id] = int(body["max_output_tokens"].(float64))
		if body["max_tokens"] != body["max_output_tokens"] {
			a.t.Error("authorization token limits disagree")
		}
		return reply(200, auth)
	case "/internal/gateway/video/jobs/prepare":
		a.prepares++
		// Apply the router's endpoint, model and billing checks to every prepare.
		if !a.validPrepare(body) {
			return reply(400, nil)
		}
		if a.prepareTransportFailure {
			return nil, fmt.Errorf("prepare transport failure")
		}
		if a.prepareStatus != 0 {
			return reply(a.prepareStatus, nil)
		}
		if a.failPrepare {
			return reply(503, nil)
		}
		id := body["job_id"].(string)
		if job, ok := a.jobs[id]; ok {
			job.Created = false
			return reply(200, job)
		}
		raw, _ := json.Marshal(body)
		var job trustedrouter.VideoJob
		if err := json.Unmarshal(raw, &job); err != nil {
			a.t.Fatal(err)
		}
		job.ID = id
		job.WorkspaceID = "ws"
		job.KeyHash = "hash"
		job.Status = "submitting"
		a.jobs[id] = job
		a.order = append(a.order, id)
		a.due[id] = a.now.Add(300 * time.Second)
		job.Created = !a.existingPrepare
		return reply(200, job)
	case "/internal/gateway/refund":
		a.refunds = append(a.refunds, body)
		if a.hangRefund {
			deadline, ok := r.Context().Deadline()
			if !ok {
				a.t.Fatal("refund has no deadline")
			}
			a.refundBudget = time.Until(deadline)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		if a.failRefund {
			return reply(503, nil)
		}
		id := body["authorization_id"].(string)
		if a.held[id] {
			a.held[id] = false
			a.releases++
		}
		return reply(200, map[string]any{"refunded": true, "already_settled": true})
	case "/internal/gateway/video/jobs/claim":
		if body["lease_seconds"] != float64(60) {
			a.t.Errorf("lease=%v", body)
		}
		var jobs []trustedrouter.VideoJob
		for _, id := range a.order {
			job := a.jobs[id]
			if len(jobs) >= int(body["limit"].(float64)) {
				break
			}
			if (job.Status == "submitting" || job.Status == "pending" || job.Status == "in_progress") && !a.due[id].After(a.now) && !a.lease[id].After(a.now) {
				a.lease[id] = a.now.Add(60 * time.Second)
				jobs = append(jobs, job)
			}
		}
		return reply(200, jobs)
	case "/internal/gateway/settle":
		a.settlements++
		return reply(200, map[string]any{"settled": true, "generation_id": "generation"})
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 7 {
		a.t.Errorf("unexpected call: %s", r.URL.Path)
		return reply(500, nil)
	}
	id := parts[5]
	job, ok := a.jobs[id]
	if !ok {
		return reply(404, nil)
	}
	switch parts[6] {
	case "lookup":
		a.lookups++
		if body["api_key_lookup_hash"] != trustedrouter.LookupHash("test") {
			a.t.Error("unscoped lookup")
		}
	case "update":
		if a.failUpdate {
			return reply(503, nil)
		}
		job.Status = body["status"].(string)
		job.LastError, _ = body["error"].(string)
		if job.Status == "failed" && a.held[job.AuthorizationID] {
			a.t.Error("terminal row before refund")
		}
		a.jobs[id] = job
	case "queued":
		job.Status = "pending"
		job.ProviderJobID = body["provider_job_id"].(string)
		job.Provider = body["provider"].(string)
		job.EndpointID = body["endpoint_id"].(string)
		a.jobs[id] = job
	default:
		a.t.Errorf("unexpected mutation: %s", r.URL.Path)
		return reply(500, nil)
	}
	return reply(200, job)
}

func (a *refundAuthority) validPrepare(body map[string]any) bool {
	auth := a.authorizationRows[body["authorization_id"].(string)]
	if auth == nil || body["model"] != auth["model"] {
		return false
	}
	matches := func(route map[string]any) bool {
		return body["endpoint_id"] == route["endpoint_id"] && body["provider"] == route["provider"] &&
			(route["model"] == nil || route["model"] == body["model"])
	}
	allowed := matches(auth)
	candidates, _ := auth["route_candidates"].([]map[string]any)
	for _, candidate := range candidates {
		allowed = allowed || matches(candidate)
	}
	if !allowed {
		return false
	}
	quoted := int(body["quoted_microdollars"].(float64))
	if quoted > auth["additional_cost_reservation_microdollars"].(int) {
		return false
	}
	if body["provider"] == "byteplus" {
		limit, _ := body["output_token_limit"].(float64)
		return quoted == 0 && limit > 0 && limit <= float64(a.authorizedLimits[auth["authorization_id"].(string)])
	}
	return quoted > 0
}

type refundTestProvider struct {
	video.Provider
	queues, polls int
	seed          *int64
}

func (p *refundTestProvider) QueueResolved(_ context.Context, r *video.ResolvedRequest) (*video.QueueResult, error) {
	p.queues++
	p.seed = r.Seed
	return &video.QueueResult{QueueID: "provider-job", ProviderModel: r.Model.ID}, nil
}
func (p *refundTestProvider) Retrieve(context.Context, string, string) (*video.PollResult, error) {
	p.polls++
	return &video.PollResult{State: video.PollCompleted, ProviderStatus: "COMPLETED"}, nil
}
func (a *refundAuthority) service() (*videoService, *refundTestProvider, *refundTestProvider) {
	client := &http.Client{Transport: a}
	fal := &refundTestProvider{Provider: video.NewFALVideoClientAt("test", "http://provider.invalid", client)}
	venice := &refundTestProvider{Provider: video.NewVeniceClientAt("test", "http://provider.invalid", client)}
	return &videoService{control: trustedrouter.New("http://127.0.0.1:18082,http://127.0.0.1:18081", "internal", client), providers: video.NewRegistryWithProviders(fal, venice), workerID: "worker"}, fal, venice
}
func refundCreate(t *testing.T, s *videoService, key string, seed bool) string {
	t.Helper()
	body := `{"model":"minimax/h3-max","prompt":"cube"}`
	if seed {
		body = `{"model":"minimax/h3-max","prompt":"cube","seed":1101}`
	}
	var out bytes.Buffer
	s.serveCreate(t.Context(), &out, []byte(body), "test", key)
	return out.String()
}
func (a *refundAuthority) submitting(key string) trustedrouter.VideoJob {
	a.t.Helper()
	job, ok := a.jobs[trustedrouter.VideoJobID("auth-"+key)]
	if !ok || job.Status != "submitting" || job.ProviderJobID != "" || job.Provider != "venice" || job.EndpointID != "primary" || job.QuotedMicrodollars != 500000 {
		a.t.Fatalf("missing durable primary submission: %+v", job)
	}
	return job
}
func TestVideoRoutingRefundRestart(t *testing.T) {
	for _, failure := range []string{"refund", "update"} {
		t.Run(failure, func(t *testing.T) {
			a := newRefundAuthority(t)
			a.failRefund = failure == "refund"
			a.failUpdate = failure == "update"
			s, fal, venice := a.service()
			out := refundCreate(t, s, "restart", true)
			if !strings.Contains(out, `"code":"video_routing_unavailable"`) {
				t.Fatal(out)
			}
			job := a.submitting("restart")
			if fal.queues+venice.queues != 0 {
				t.Fatal("incompatible dispatch")
			}
			// No client, provider or video-service object survives the restart.
			fresh, _, _ := a.service()
			// Reordering endpoints also proves claims re-pin to the row's authority.
			fresh.control = trustedrouter.New("http://127.0.0.1:18081,http://127.0.0.1:18082", "internal", &http.Client{Transport: a})
			a.failRefund = false
			a.failUpdate = false
			if n, err := fresh.drain(t.Context()); n != 0 || err != nil {
				t.Fatalf("claimed before due: %d %v", n, err)
			}
			a.now = a.now.Add(300 * time.Second)
			if n, err := fresh.drain(t.Context()); n != 1 || err != nil {
				t.Fatalf("restart drain: %d %v", n, err)
			}
			if a.jobs[job.ID].Status != "failed" || a.held[job.AuthorizationID] || a.releases != 1 || len(a.refunds) != 2 {
				t.Fatalf("refund lost or duplicated: %+v", a)
			}
			if a.refunds[1]["error_type"] != "video_submission_interrupted" || a.refunds[1]["authorization_id"] != job.AuthorizationID {
				t.Fatalf("wrong worker refund: %v", a.refunds)
			}
		})
	}
}
func TestVideoRoutingRefundCallerRetry(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprint(restart), func(t *testing.T) {
			a := newRefundAuthority(t)
			a.failRefund = true
			s, _, _ := a.service()
			_ = refundCreate(t, s, "retry", true)
			if restart {
				s, _, _ = a.service()
			}
			out := refundCreate(t, s, "retry", true)
			if !strings.HasPrefix(out, "HTTP/1.1 202 ") || videoHTTPBody(t, out)["id"] != trustedrouter.VideoJobID("auth-retry") {
				t.Fatal(out)
			}
			if a.newHolds != 1 || a.prepares != 1 || a.lookups != 1 || len(a.refunds) != 1 {
				t.Fatalf("retry created work: %+v", a)
			}
		})
	}
}
func TestVideoRoutingRefundNoEnclaveObligations(t *testing.T) {
	a := newRefundAuthority(t)
	a.failRefund = true
	s, _, _ := a.service()
	for i := range 32 {
		key := fmt.Sprint(i)
		_ = refundCreate(t, s, key, true)
		a.submitting(key)
	}
	if a.newHolds != 32 || len(a.jobs) != 32 || a.prepares != 32 {
		t.Fatalf("not one row per authorization: %+v", a)
	}
	typ := reflect.TypeOf(s.control).Elem()
	for i := range typ.NumField() {
		if strings.HasPrefix(typ.Field(i).Name, "videoRefund") {
			t.Fatalf("enclave retained obligation state: %s", typ.Field(i).Name)
		}
	}
	before := len(a.refunds)
	if n, err := s.drain(t.Context()); n != 0 || err != nil || len(a.refunds) != before {
		t.Fatalf("unclaimed refund obligations drained: %d %v", n, err)
	}
}
func TestVideoRoutingRefundPollingDuringOutage(t *testing.T) {
	a := newRefundAuthority(t)
	a.failRefund = true
	s, fal, _ := a.service()
	_ = refundCreate(t, s, "outage", true)
	a.hangRefund = true
	unrelated := trustedrouter.VideoJob{ID: "job-unrelated", AuthorizationID: "unrelated", Provider: "fal", EndpointID: "fallback", Model: "minimax/h3-max", ProviderModel: "minimax/h3-max", ProviderJobID: "working", Status: "pending", QuotedMicrodollars: 500000}
	a.jobs[unrelated.ID] = unrelated
	a.order = append(a.order, unrelated.ID)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	before := len(a.refunds)
	n, err := s.drain(ctx)
	if err != nil || n != 1 || fal.polls != 1 || a.settlements != 1 || a.jobs[unrelated.ID].Status != "completed" || len(a.refunds) != before {
		t.Fatalf("refund outside claimed rows blocked polling: n=%d err=%v polls=%d refunds=%d", n, err, fal.polls, len(a.refunds)-before)
	}
}
func TestVideoRoutingRefundClaimTimeoutAndLeaseRetry(t *testing.T) {
	a := newRefundAuthority(t)
	a.failRefund = true
	s, _, _ := a.service()
	_ = refundCreate(t, s, "timeout", true)
	job := a.submitting("timeout")
	a.now = a.now.Add(300 * time.Second)
	a.hangRefund = true
	start := time.Now()
	if n, err := s.drain(t.Context()); n != 1 || err != nil {
		t.Fatalf("drain: %d %v", n, err)
	}
	// Refund has its own 10s deadline inside the worker's 45s per-job budget.
	if elapsed := time.Since(start); elapsed > 15*time.Second || a.refundBudget <= 0 || a.refundBudget > 45*time.Second {
		t.Fatalf("unbounded claimed refund: elapsed=%v budget=%v", elapsed, a.refundBudget)
	}
	if a.jobs[job.ID].Status != "submitting" || !a.held[job.AuthorizationID] {
		t.Fatal("lost obligation after timeout")
	}
	a.hangRefund = false
	a.failRefund = false
	if n, err := s.drain(t.Context()); n != 0 || err != nil {
		t.Fatalf("ignored lease: %d %v", n, err)
	}
	a.now = a.now.Add(60 * time.Second)
	if n, err := s.drain(t.Context()); n != 1 || err != nil || a.jobs[job.ID].Status != "failed" || a.held[job.AuthorizationID] {
		t.Fatalf("lease retry: %d %v", n, err)
	}
}
func TestVideoSeedLegacyCompatibleFallback(t *testing.T) {
	a := newRefundAuthority(t)
	a.compatibleFallback = true
	s, fal, venice := a.service()
	out := refundCreate(t, s, "fallback", true)
	if !strings.HasPrefix(out, "HTTP/1.1 202 ") || fal.queues != 1 || fal.seed == nil || *fal.seed != 1101 || venice.queues != 0 || len(a.refunds) != 0 {
		t.Fatalf("response=%s fal=%+v venice=%+v refunds=%v", out, fal, venice, a.refunds)
	}
	job := a.jobs[trustedrouter.VideoJobID("auth-fallback")]
	if job.Provider != "fal" || job.EndpointID != "fallback" {
		t.Fatalf("wrong route: %+v", job)
	}
}
func TestVideoUnseededNoRouteMainParity(t *testing.T) {
	a := newRefundAuthority(t)
	s, _, _ := a.service()
	// Only FAL is configured, so the authorized Venice route has no quote.
	fal, _ := s.providers.Provider("fal")
	s.providers = video.NewRegistryWithProviders(fal)
	got := refundCreate(t, s, "unseeded", false)
	var want bytes.Buffer
	writeOpenAIError(&want, 503, "no authorized video provider supports this request", "server_error", "video_provider_unavailable", "")
	if got != want.String() || len(a.jobs) != 0 || a.prepares != 0 || len(a.refunds) != 1 || a.refunds[0]["error_type"] != "video_provider_unavailable" {
		t.Fatalf("unseeded parity: %q, jobs=%v refunds=%v", got, a.jobs, a.refunds)
	}
}
func TestVideoRoutingRejectionPrepareOutcomes(t *testing.T) {
	for _, outcome := range []string{"unavailable", "existing", "created"} {
		t.Run(outcome, func(t *testing.T) {
			a := newRefundAuthority(t)
			a.failPrepare = outcome == "unavailable"
			a.existingPrepare = outcome == "existing"
			s, fal, venice := a.service()
			out := refundCreate(t, s, "prepare", true)
			switch outcome {
			case "unavailable":
				if !strings.Contains(out, `"code":"video_job_store_unavailable"`) || len(a.jobs) != 0 || len(a.refunds) != 1 || a.refunds[0]["error_type"] != "video_job_store_unavailable" {
					t.Fatal(out)
				}
			case "existing":
				if !strings.HasPrefix(out, "HTTP/1.1 202 ") || len(a.refunds) != 0 {
					t.Fatal(out)
				}
			case "created":
				job := a.jobs[trustedrouter.VideoJobID("auth-prepare")]
				if !strings.Contains(out, `"code":"video_routing_unavailable"`) || job.Status != "failed" || job.LastError != "routing_unavailable" || a.releases != 1 {
					t.Fatalf("%s job=%+v releases=%d", out, job, a.releases)
				}
			}
			if fal.queues+venice.queues != 0 {
				t.Fatal("rejected row dispatched")
			}
		})
	}
}
