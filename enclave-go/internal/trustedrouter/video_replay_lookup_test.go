package trustedrouter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLookupVideoReplayReadOnlyAndAuthorityScoped(t *testing.T) {
	for _, tc := range []string{"valid", "all_miss", "no_key", "dial_then_found", "dial_then_miss", "unsupported_endpoint", "fingerprint_conflict", "credential_rejected", "missing_marker", "fresh_authority", "missing_scope", "wrong_model", "missing_job", "wrong_job_id", "wrong_job_authorization", "wrong_job_workspace", "wrong_job_key", "wrong_job_model", "job_unavailable"} {
		t.Run(tc, func(t *testing.T) {
			const model = "minimax/hailuo-3"
			auth := &Authorization{AuthorizationID: "old", WorkspaceID: "ws", APIKeyHash: "hash", Model: model, IdempotentReplay: true}
			job := VideoJob{ID: VideoJobID("old"), AuthorizationID: "old", WorkspaceID: "ws", KeyHash: "hash", Model: model, Status: "completed", Created: true}
			key := "old-key"
			wantStatus, wantReplay, wantJobs := 409, 2, 0
			switch tc {
			case "valid", "dial_then_found":
				wantStatus, wantJobs = 0, 1
			case "all_miss":
				wantStatus = 0
			case "no_key":
				key, wantStatus, wantReplay = "", 0, 0
			case "dial_then_miss", "unsupported_endpoint":
				wantStatus = 503
			case "fingerprint_conflict":
				wantReplay = 1
			case "credential_rejected":
				wantStatus, wantReplay = 401, 1
			case "fresh_authority":
				auth.IdempotentReplay = false
			case "missing_scope":
				auth.WorkspaceID = ""
			case "wrong_model":
				auth.Model = "other"
			case "missing_job":
				wantJobs = 1
			case "wrong_job_id":
				job.ID, wantJobs = "wrong", 1
			case "wrong_job_authorization":
				job.AuthorizationID, wantJobs = "wrong", 1
			case "wrong_job_workspace":
				job.WorkspaceID, wantJobs = "wrong", 1
			case "wrong_job_key":
				job.KeyHash, wantJobs = "wrong", 1
			case "wrong_job_model":
				job.Model, wantJobs = "wrong", 1
			case "job_unavailable":
				wantStatus, wantJobs = 503, 1
			}
			replayCalls, jobCalls := 0, 0
			client := New("http://127.0.0.1:18081,http://127.0.0.1:18082", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				reply := func(status int, data any) (*http.Response, error) {
					raw, err := json.Marshal(data)
					if err != nil {
						return nil, err
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["api_key_lookup_hash"] != LookupHash("caller") || r.Header.Get("X-Quill-Video-Allowed-Providers") != "" {
					t.Errorf("unscoped or leaked lookup: %v", body)
				}
				switch r.URL.Path {
				case "/internal/gateway/video/replay-lookup":
					replayCalls++
					if body["idempotency_key"] != key || body["request_fingerprint"] != strings.Repeat("a", 64) || body["additional_cost_reservation_microdollars"] != nil || body["invocation_nonce"] != nil {
						t.Errorf("lookup identity/mutation: %v", body)
					}
					if tc == "fingerprint_conflict" {
						return reply(409, map[string]any{})
					}
					if tc == "credential_rejected" {
						return reply(401, map[string]any{})
					}
					if tc == "unsupported_endpoint" {
						return reply(404, map[string]any{})
					}
					if r.URL.Host == "127.0.0.1:18081" {
						if strings.HasPrefix(tc, "dial_then_") {
							return nil, &dialFailure{err: errors.New("unavailable")}
						}
						return reply(200, map[string]any{"data": map[string]any{"found": false}})
					}
					if tc == "all_miss" || tc == "dial_then_miss" {
						return reply(200, map[string]any{"data": map[string]any{"found": false}})
					}
					if tc == "missing_marker" {
						return reply(200, map[string]any{"data": map[string]any{"authorization": auth}})
					}
					return reply(200, map[string]any{"data": map[string]any{"found": true, "authorization": auth}})
				case "/internal/gateway/video/jobs/" + VideoJobID("old") + "/lookup":
					jobCalls++
					if r.URL.Host != "127.0.0.1:18082" {
						t.Error("job lookup changed billing authority")
					}
					if tc == "missing_job" {
						return reply(404, map[string]any{})
					}
					if tc == "job_unavailable" {
						return reply(503, map[string]any{})
					}
					return reply(200, map[string]any{"data": job})
				default:
					t.Errorf("read-only recovery attempted mutation: %s", r.URL.Path)
					return reply(500, map[string]any{})
				}
			})})
			got, err := client.LookupVideoReplay(t.Context(), "caller", model, key, strings.Repeat("a", 64), nil)
			if wantStatus == 0 {
				if err != nil {
					t.Fatal(err)
				}
				if wantJobs == 1 && (got == nil || got.Created || got.ControlPlaneEndpoint != 1 || !got.ControlPlaneEndpointSet) {
					t.Fatalf("bad recovered job: %+v", got)
				}
				if wantJobs == 0 && got != nil {
					t.Fatalf("miss recovered job: %+v", got)
				}
			} else {
				var cp *ControlPlaneError
				if got != nil || !errors.As(err, &cp) || cp.StatusCode != wantStatus {
					t.Fatalf("got job=%v err=%v want %d", got, err, wantStatus)
				}
			}
			if replayCalls != wantReplay || jobCalls != wantJobs {
				t.Fatalf("replay=%d jobs=%d want %d/%d", replayCalls, jobCalls, wantReplay, wantJobs)
			}
		})
	}
}
