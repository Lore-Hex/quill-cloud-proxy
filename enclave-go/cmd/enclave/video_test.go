package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func videoHTTPBody(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid raw HTTP response %q", raw)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(parts[1]), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return payload
}

func TestParseVideoJobPath(t *testing.T) {
	tests := []struct {
		path        string
		wantID      string
		wantContent bool
		wantOK      bool
	}{
		{path: "/v1/videos/job-abc123", wantID: "job-abc123", wantOK: true},
		{path: "/v1/videos/job-abc123/content", wantID: "job-abc123", wantContent: true, wantOK: true},
		{path: "/v1/videos/abc123", wantOK: false},
		{path: "/v1/videos/job-a/extra", wantOK: false},
		{path: "/v1/videos/", wantOK: false},
	}
	for _, tc := range tests {
		id, content, ok := parseVideoJobPath(tc.path)
		if id != tc.wantID || content != tc.wantContent || ok != tc.wantOK {
			t.Fatalf("parseVideoJobPath(%q) = %q,%t,%t", tc.path, id, content, ok)
		}
	}
}

func TestVideoJobIDIsDeterministicAndAuthorizationScoped(t *testing.T) {
	a := videoJobID("auth-1")
	if a != videoJobID("auth-1") || a == videoJobID("auth-2") || !strings.HasPrefix(a, "job-") {
		t.Fatalf("bad deterministic IDs: %q", a)
	}
}

func TestVideoRequestFingerprintBindsContentWithoutExposingIt(t *testing.T) {
	a := videoRequestFingerprint("secret-key", &video.CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "private prompt", Duration: 5,
	})
	b := videoRequestFingerprint("secret-key", &video.CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "different prompt", Duration: 5,
	})
	c := videoRequestFingerprint("secret-key", &video.CreateRequest{
		Model: "minimax/hailuo-3", Prompt: "private prompt", Duration: 6,
	})
	if len(a) != 64 || a == b || a == c || strings.Contains(a, "private") {
		t.Fatalf("bad request fingerprints: %q %q %q", a, b, c)
	}
}

func TestVideoPollStateBacksOffWhenQueueIsIdleAndResetsAfterWork(t *testing.T) {
	state := videoPollState{}
	workerID := "video-test-worker"

	first := state.nextDelay(workerID, 0, nil)
	second := state.nextDelay(workerID, 0, nil)
	third := state.nextDelay(workerID, 0, nil)
	fourth := state.nextDelay(workerID, 0, nil)
	if !(first < second && second < third) {
		t.Fatalf("idle delays did not increase: %s, %s, %s", first, second, third)
	}
	for _, delay := range []time.Duration{third, fourth} {
		if delay < 25*time.Second || delay > 35*time.Second {
			t.Fatalf("capped idle delay = %s, want about 30s", delay)
		}
	}

	active := state.nextDelay(workerID, 2, nil)
	if active < 4*time.Second || active > 6*time.Second {
		t.Fatalf("active delay = %s, want about 5s", active)
	}
	if state.consecutiveIdle != 0 {
		t.Fatalf("idle state did not reset: %d", state.consecutiveIdle)
	}
}

func TestVideoPollStateDesynchronizesWorkersAndBacksOffErrors(t *testing.T) {
	left := videoPollState{}
	right := videoPollState{}
	leftDelay := left.nextDelay("video-worker-left", 0, context.DeadlineExceeded)
	rightDelay := right.nextDelay("video-worker-right", 0, context.DeadlineExceeded)
	if leftDelay == rightDelay {
		t.Fatalf("worker jitter unexpectedly matched: %s", leftDelay)
	}
	for _, delay := range []time.Duration{leftDelay, rightDelay} {
		if delay < 12*time.Second || delay > 18*time.Second {
			t.Fatalf("error delay = %s, want jittered 15s floor", delay)
		}
	}
}

func TestVideoCreateQuotesThenAuthorizesBeforeSendingPromptToProvider(t *testing.T) {
	events := make([]string, 0, 5)
	var authorizeBody map[string]any
	var prepareBody map[string]any
	var queueBody map[string]any
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/quote":
			events = append(events, "quote")
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["prompt"] != nil {
				t.Fatalf("quote leaked prompt: %#v", body)
			}
			_, _ = io.WriteString(w, `{"quote":0.40}`)
		case "/queue":
			events = append(events, "queue")
			if err := json.NewDecoder(r.Body).Decode(&queueBody); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"model":"ltx-2-v2-3-fast-text-to-video","queue_id":"provider-job-1"}`)
		default:
			t.Fatalf("unexpected provider path %q", r.URL.Path)
		}
	}))
	defer provider.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			events = append(events, "authorize")
			if err := json.NewDecoder(r.Body).Decode(&authorizeBody); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth-video-1","workspace_id":"ws-1","api_key_hash":"key-hash","model":"lightricks/ltx-2.3-fast","requested_model":"lightricks/ltx-2.3-fast","endpoint_id":"lightricks/ltx-2.3-fast@venice/prepaid","provider":"venice","usage_type":"Credits","limit_usage_type":"Credits","additional_cost_reservation_microdollars":480000,"region":"us-central1"}}`)
		case "/internal/gateway/video/jobs/prepare":
			events = append(events, "prepare")
			if err := json.NewDecoder(r.Body).Decode(&prepareBody); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"data":{"id":"job-test","workspace_id":"ws-1","key_hash":"key-hash","authorization_id":"auth-video-1","model":"lightricks/ltx-2.3-fast","provider":"venice","endpoint_id":"lightricks/ltx-2.3-fast@venice/prepaid","provider_model":"ltx-2-v2-3-fast-text-to-video","quoted_microdollars":480000,"input_mode":"text","duration_seconds":6,"resolution":"1080p","aspect_ratio":"16:9","generate_audio":true,"region":"us-central1","status":"submitting","created":true}}`)
		case "/internal/gateway/video/jobs/job-test/queued":
			events = append(events, "queued")
			_, _ = io.WriteString(w, `{"data":{"id":"job-test","workspace_id":"ws-1","key_hash":"key-hash","authorization_id":"auth-video-1","model":"lightricks/ltx-2.3-fast","provider":"venice","endpoint_id":"lightricks/ltx-2.3-fast@venice/prepaid","provider_model":"ltx-2-v2-3-fast-text-to-video","provider_job_id":"provider-job-1","quoted_microdollars":480000,"status":"pending"}}`)
		default:
			t.Fatalf("unexpected control path %q", r.URL.Path)
		}
	}))
	defer control.Close()

	controlClient := trustedrouter.New(control.URL, "internal", control.Client())
	service := &videoService{
		providers: video.NewRegistryWithProviders(
			video.NewVeniceClientAt("venice-secret", provider.URL, provider.Client()),
		),
		control:  controlClient,
		workerID: "test-worker",
	}
	requestBody := []byte(`{"model":"lightricks/ltx-2.3-fast","prompt":"private launch prompt","duration":6}`)
	var response bytes.Buffer
	service.serveCreate(context.Background(), &response, requestBody, "sk-private", "idem-video")

	if !strings.Contains(response.String(), "HTTP/1.1 202") {
		t.Fatalf("create response = %q", response.String())
	}
	payload := videoHTTPBody(t, response.String())
	if payload["id"] != "job-test" || payload["status"] != "pending" {
		t.Fatalf("public job = %#v", payload)
	}
	if strings.Join(events, ",") != "quote,authorize,prepare,queue,queued" {
		t.Fatalf("event order = %#v", events)
	}
	encodedAuth, _ := json.Marshal(authorizeBody)
	if strings.Contains(string(encodedAuth), "private launch prompt") || authorizeBody["request_fingerprint"] == nil {
		t.Fatalf("unsafe authorize payload: %s", encodedAuth)
	}
	if authorizeBody["additional_cost_reservation_microdollars"] != float64(480_000) {
		t.Fatalf("video fee not applied to authorization: %#v", authorizeBody)
	}
	encodedPrepare, _ := json.Marshal(prepareBody)
	if strings.Contains(string(encodedPrepare), "private launch prompt") ||
		prepareBody["duration_seconds"] != float64(6) ||
		prepareBody["resolution"] != "1080p" ||
		prepareBody["generate_audio"] != true {
		t.Fatalf("bad content-free video metadata: %s", encodedPrepare)
	}
	if queueBody["prompt"] != "private launch prompt" {
		t.Fatalf("provider queue did not receive prompt: %#v", queueBody)
	}
}

func TestVideoCreateFallsBackAfterRetryableDirectProviderFailure(t *testing.T) {
	events := make([]string, 0, 8)
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events = append(events, "minimax-queue")
		if r.URL.Path != "/v2/video_generation" {
			t.Fatalf("unexpected MiniMax path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"temporary"}`)
	}))
	defer direct.Close()
	venice := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/quote":
			events = append(events, "venice-quote")
			_, _ = io.WriteString(w, `{"quote":0.80}`)
		case "/queue":
			events = append(events, "venice-queue")
			_, _ = io.WriteString(w, `{"model":"minimax-h3-text-to-video","queue_id":"venice-job"}`)
		default:
			t.Fatalf("unexpected Venice path %q", r.URL.Path)
		}
	}))
	defer venice.Close()

	var authorizeBody map[string]any
	var prepareBody map[string]any
	var queuedBody map[string]any
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			events = append(events, "authorize")
			if err := json.NewDecoder(r.Body).Decode(&authorizeBody); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth-fallback","workspace_id":"ws-1","api_key_hash":"key-hash","model":"minimax/hailuo-3","requested_model":"minimax/hailuo-3","endpoint_id":"minimax/hailuo-3@minimax/prepaid","provider":"minimax","usage_type":"Credits","limit_usage_type":"Credits","additional_cost_reservation_microdollars":960000,"region":"us-central1","route_candidates":[{"endpoint_id":"minimax/hailuo-3@minimax/prepaid","model":"minimax/hailuo-3","provider":"minimax","usage_type":"Credits"},{"endpoint_id":"minimax/hailuo-3@venice/prepaid","model":"minimax/hailuo-3","provider":"venice","usage_type":"Credits"}]}}`)
		case "/internal/gateway/video/jobs/prepare":
			events = append(events, "prepare")
			if err := json.NewDecoder(r.Body).Decode(&prepareBody); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"data":{"id":"job-fallback","workspace_id":"ws-1","key_hash":"key-hash","authorization_id":"auth-fallback","model":"minimax/hailuo-3","provider":"minimax","endpoint_id":"minimax/hailuo-3@minimax/prepaid","provider_model":"minimax/hailuo-3","quoted_microdollars":780000,"input_mode":"text","duration_seconds":5,"resolution":"2K","aspect_ratio":"16:9","generate_audio":true,"region":"us-central1","status":"submitting","created":true}}`)
		case "/internal/gateway/video/jobs/job-fallback/queued":
			events = append(events, "queued")
			if err := json.NewDecoder(r.Body).Decode(&queuedBody); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"data":{"id":"job-fallback","workspace_id":"ws-1","key_hash":"key-hash","authorization_id":"auth-fallback","model":"minimax/hailuo-3","provider":"venice","endpoint_id":"minimax/hailuo-3@venice/prepaid","provider_model":"minimax-h3-text-to-video","provider_job_id":"venice-job","quoted_microdollars":960000,"status":"pending"}}`)
		default:
			t.Fatalf("unexpected control path %q", r.URL.Path)
		}
	}))
	defer control.Close()

	service := &videoService{
		providers: video.NewRegistryWithProviders(
			video.NewMiniMaxClientAt("minimax-secret", direct.URL, direct.Client()),
			video.NewVeniceClientAt("venice-secret", venice.URL, venice.Client()),
		),
		control: trustedrouter.New(control.URL, "internal", control.Client()),
	}
	var response bytes.Buffer
	service.serveCreate(
		context.Background(), &response,
		[]byte(`{"model":"minimax/hailuo-3","prompt":"private fallback prompt","duration":5}`),
		"sk-private", "idem-fallback",
	)
	if !strings.Contains(response.String(), "HTTP/1.1 202") {
		t.Fatalf("create response = %q", response.String())
	}
	if authorizeBody["additional_cost_reservation_microdollars"] != float64(960_000) {
		t.Fatalf("authorization did not reserve the maximum fallback quote: %#v", authorizeBody)
	}
	if prepareBody["provider"] != "minimax" || prepareBody["quoted_microdollars"] != float64(780_000) {
		t.Fatalf("prepare did not record the initially selected direct route: %#v", prepareBody)
	}
	if queuedBody["provider"] != "venice" ||
		queuedBody["endpoint_id"] != "minimax/hailuo-3@venice/prepaid" ||
		queuedBody["quoted_microdollars"] != float64(960_000) {
		t.Fatalf("queued transition did not persist the selected fallback: %#v", queuedBody)
	}
	wantEvents := "venice-quote,authorize,prepare,minimax-queue,venice-queue,queued"
	if strings.Join(events, ",") != wantEvents {
		t.Fatalf("events = %q, want %q", strings.Join(events, ","), wantEvents)
	}
}

func TestCompletedVideoSettlesBeforePublishingCompletedState(t *testing.T) {
	events := make([]string, 0, 3)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/retrieve" {
			t.Fatalf("provider path = %q", r.URL.Path)
		}
		events = append(events, "retrieve")
		w.Header().Set("Content-Type", "video/mp4")
		_, _ = io.WriteString(w, "video-bytes")
	}))
	defer provider.Close()
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/settle":
			events = append(events, "settle")
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["additional_cost_microdollars"] != float64(850_500) || body["route_type"] != "videos" ||
				body["video_duration_seconds"] != float64(5) || body["video_resolution"] != "2K" ||
				body["video_generate_audio"] != true {
				t.Fatalf("settle body = %#v", body)
			}
			_, _ = io.WriteString(w, `{"data":{"generation_id":"gen-video","cost_microdollars":850500}}`)
		case "/internal/gateway/video/jobs/job-complete/update":
			events = append(events, "update")
			_, _ = io.WriteString(w, `{"data":{"id":"job-complete","authorization_id":"auth-video","workspace_id":"ws","key_hash":"key","model":"minimax/hailuo-3","provider":"venice","endpoint_id":"minimax/hailuo-3@venice/prepaid","provider_model":"minimax-h3-text-to-video","provider_job_id":"provider-job","quoted_microdollars":850500,"status":"completed","provider_status":"COMPLETED","generation_id":"gen-video"}}`)
		default:
			t.Fatalf("control path = %q", r.URL.Path)
		}
	}))
	defer control.Close()
	service := &videoService{
		providers: video.NewRegistryWithProviders(
			video.NewVeniceClientAt("venice-secret", provider.URL, provider.Client()),
		),
		control: trustedrouter.New(control.URL, "internal", control.Client()),
	}
	job := &trustedrouter.VideoJob{
		ID: "job-complete", AuthorizationID: "auth-video", WorkspaceID: "ws", KeyHash: "key",
		Model: "minimax/hailuo-3", Provider: "venice", EndpointID: "minimax/hailuo-3@venice/prepaid",
		ProviderModel: "minimax-h3-text-to-video", ProviderJobID: "provider-job",
		QuotedMicrodollars: 850_500, Status: "pending",
		InputMode: "text", DurationSeconds: 5, Resolution: "2K", AspectRatio: "16:9",
		GenerateAudio: true,
	}
	completed, err := service.pollAndFinalize(context.Background(), job, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.GenerationID != "gen-video" {
		t.Fatalf("completed job = %#v", completed)
	}
	if strings.Join(events, ",") != "retrieve,settle,update" {
		t.Fatalf("settlement order = %#v", events)
	}
}

func TestPublicVideoJobResponseDoesNotExposeInternalMetadata(t *testing.T) {
	job := &trustedrouter.VideoJob{
		ID: "job-public", WorkspaceID: "secret-workspace", KeyHash: "secret-key-hash",
		AuthorizationID: "secret-auth", Model: "minimax/hailuo-3", Provider: "venice",
		ProviderModel: "minimax-h3-text-to-video", ProviderJobID: "secret-provider-job",
		QuotedMicrodollars: 850_500, Status: "completed", GenerationID: "gen-public",
		ContentExpiresAt: "2026-08-01T00:00:00Z",
	}
	var raw bytes.Buffer
	writeVideoJobResponse(&raw, 200, job)
	parts := strings.SplitN(raw.String(), "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid HTTP response %q", raw.String())
	}
	for _, secret := range []string{"secret-workspace", "secret-key-hash", "secret-auth", "secret-provider-job", "minimax-h3-text-to-video"} {
		if strings.Contains(parts[1], secret) {
			t.Fatalf("public response leaked %q: %s", secret, parts[1])
		}
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(parts[1]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != "completed" || payload["expires_at"] != "2026-08-01T00:00:00Z" {
		t.Fatalf("bad public payload: %#v", payload)
	}
	usage := payload["usage"].(map[string]any)
	if usage["cost_microdollars"] != float64(850_500) || usage["cost"] != 0.8505 {
		t.Fatalf("bad exact cost: %#v", usage)
	}
}

func TestVideoContentHeadersForbidCaching(t *testing.T) {
	var raw bytes.Buffer
	if err := writeVideoResponseHead(&raw, "video/mp4", "job-123"); err != nil {
		t.Fatal(err)
	}
	headers := raw.String()
	for _, expected := range []string{"Cache-Control: no-store", "Content-Type: video/mp4", "X-Content-Type-Options: nosniff", `filename="job-123.mp4"`} {
		if !strings.Contains(headers, expected) {
			t.Fatalf("missing header %q in %q", expected, headers)
		}
	}
}

func TestVideoContentCleansUpAfterVeniceCompleteBadRequest(t *testing.T) {
	providerRequests := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerRequests++
		switch r.URL.Path {
		case "/retrieve":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "video/mp4")
			if body["delete_media_on_completion"] == true {
				_, _ = io.WriteString(w, "cleanup-copy")
				return
			}
			_, _ = io.WriteString(w, "video-bytes")
		case "/complete":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"Request ID is invalid."}`)
		default:
			t.Fatalf("unexpected provider path %q", r.URL.Path)
		}
	}))
	defer provider.Close()

	cleaned := false
	cleanCalls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/video/jobs/job-delivery/lookup":
			job := map[string]any{
				"id": "job-delivery", "status": "completed",
				"provider":        "venice",
				"provider_model":  "minimax-h3-text-to-video",
				"provider_job_id": "provider-job",
			}
			if cleaned {
				job["cleaned_at"] = "2026-07-31T00:00:00Z"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": job})
		case "/internal/gateway/video/jobs/job-delivery/cleaned":
			cleanCalls++
			cleaned = true
			_, _ = io.WriteString(w, `{"data":{"id":"job-delivery","cleaned_at":"2026-07-31T00:00:00Z"}}`)
		default:
			t.Fatalf("unexpected control path %q", r.URL.Path)
		}
	}))
	defer control.Close()

	service := &videoService{
		providers: video.NewRegistryWithProviders(
			video.NewVeniceClientAt("venice-secret", provider.URL, provider.Client()),
		),
		control: trustedrouter.New(control.URL, "internal", control.Client()),
	}
	var first bytes.Buffer
	service.serveContent(context.Background(), &first, "sk-private", "job-delivery")
	if !strings.Contains(first.String(), "HTTP/1.1 200 OK") || !strings.Contains(first.String(), "video-bytes") {
		t.Fatalf("first content response = %q", first.String())
	}
	if cleanCalls != 1 || providerRequests != 3 {
		t.Fatalf("cleanup calls = %d, provider requests = %d", cleanCalls, providerRequests)
	}

	var second bytes.Buffer
	service.serveContent(context.Background(), &second, "sk-private", "job-delivery")
	if !strings.Contains(second.String(), "HTTP/1.1 410 Gone") || providerRequests != 3 {
		t.Fatalf("second content response = %q; provider requests = %d", second.String(), providerRequests)
	}
}
