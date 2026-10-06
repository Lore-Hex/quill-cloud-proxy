package trustedrouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAuthorizeVideoReplayFailsClosedAndPinsOriginalAuthority(t *testing.T) {
	for _, name := range []string{
		"valid", "legacy_nonce", "missing_job", "lookup_unavailable", "lookup_forbidden",
		"wrong_id", "wrong_authorization", "wrong_workspace", "wrong_key", "wrong_model",
		"authorization_wrong_model", "authorization_missing_scope", "missing_fingerprint", "content_conflict",
	} {
		t.Run(name, func(t *testing.T) {
			const model = "bytedance/seedance-2.5"
			job := VideoJob{
				ID: VideoJobID("auth-original"), AuthorizationID: "auth-original", Model: model,
				WorkspaceID: "ws", KeyHash: "hash", Status: "completed", Created: true,
			}
			auth := Authorization{
				AuthorizationID: job.AuthorizationID, Model: model, WorkspaceID: "ws", APIKeyHash: "hash",
				IdempotentReplay: true, InvocationNonce: "old-invocation",
			}
			fingerprint := strings.Repeat("a", 64)
			wantStatus, wantLookups := http.StatusConflict, 1
			switch name {
			case "valid":
				wantStatus = 0
			case "legacy_nonce":
				auth.InvocationNonce, wantStatus = "", 0
			case "lookup_unavailable":
				wantStatus = http.StatusServiceUnavailable
			case "lookup_forbidden":
				wantStatus = http.StatusForbidden
			case "wrong_id":
				job.ID = "job-wrong"
			case "wrong_authorization":
				job.AuthorizationID = "wrong"
			case "wrong_workspace":
				job.WorkspaceID = "wrong"
			case "wrong_key":
				job.KeyHash = "wrong"
			case "wrong_model":
				job.Model = "wrong"
			case "authorization_wrong_model":
				auth.Model, wantLookups = "wrong", 0
			case "authorization_missing_scope":
				auth.WorkspaceID, wantLookups = "", 0
			case "missing_fingerprint":
				fingerprint, wantLookups = "", 0
			case "content_conflict":
				wantLookups = 0
			}
			lookups, mutations := 0, 0
			client := New("http://127.0.0.1:18081,http://127.0.0.1:18082", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				respond := func(status int, data any) (*http.Response, error) {
					body, err := json.Marshal(data)
					if err != nil {
						return nil, err
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
				}
				if r.URL.Path == "/internal/gateway/authorize" {
					if r.URL.Host == "127.0.0.1:18081" {
						return nil, &dialFailure{err: errors.New("unavailable")}
					}
					if name == "content_conflict" {
						return respond(http.StatusConflict, map[string]any{"error": map[string]any{"message": "fingerprint mismatch"}})
					}
					return respond(http.StatusOK, map[string]any{"data": auth})
				}
				if r.URL.Path == "/internal/gateway/video/jobs/"+VideoJobID("auth-original")+"/lookup" {
					lookups++
					if r.URL.Host != "127.0.0.1:18082" {
						t.Error("replay crossed billing authority")
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["api_key_lookup_hash"] != LookupHash("caller-key") {
						t.Error("lookup is not caller scoped")
					}
					status := map[string]int{"missing_job": 404, "lookup_unavailable": 503, "lookup_forbidden": 403}[name]
					if status != 0 {
						return respond(status, map[string]any{"error": map[string]any{"message": "lookup failed"}})
					}
					return respond(http.StatusOK, map[string]any{"data": job})
				}
				mutations++
				return nil, fmt.Errorf("unexpected mutation %s", r.URL.Path)
			})})
			gotAuth, gotJob, err := client.AuthorizeVideo(WithVideoAllowedProviders(t.Context(), []string{"byteplus"}), "caller-key", model, "original-key", fingerprint, nil, 0, 80_000)
			if gotAuth != nil {
				t.Fatal("replay returned dispatch authority")
			}
			if wantStatus == 0 {
				if err != nil || gotJob == nil || gotJob.Created || !gotJob.ControlPlaneEndpointSet || gotJob.ControlPlaneEndpoint != 1 {
					t.Fatalf("job=%+v err=%v", gotJob, err)
				}
			} else {
				var cp *ControlPlaneError
				if gotJob != nil || !errors.As(err, &cp) || cp.StatusCode != wantStatus {
					t.Fatalf("job=%+v err=%v want status=%d", gotJob, err, wantStatus)
				}
			}
			if lookups != wantLookups || mutations != 0 {
				t.Fatalf("lookups=%d want=%d mutations=%d", lookups, wantLookups, mutations)
			}
		})
	}
}

func TestOrdinaryAuthorizeStillRejectsVideoReplay(t *testing.T) {
	client := New("http://127.0.0.1:18081", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Request: r, Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"auth","api_key_hash":"hash","workspace_id":"ws","model":"model","idempotent_replay":true,"invocation_nonce":"old"}}`))}, nil
	})})
	for _, route := range []string{"chat.completions", "messages", "responses", "embeddings", "images", "videos"} {
		auth, err := client.AuthorizeWithRoute(t.Context(), "caller-key", &qtypes.OpenAIChatRequest{
			Model: "model", IdempotencyKey: "key", RequestFingerprint: strings.Repeat("a", 64),
		}, route)
		var cp *ControlPlaneError
		if auth != nil || !errors.As(err, &cp) || cp.StatusCode != 409 || cp.Type != "idempotency_replay" {
			t.Fatalf("%s acquired dispatch rights: auth=%+v err=%v", route, auth, err)
		}
	}
}

func TestAuthorizeVideoConstraintsFailClosedOnLegacyRouter(t *testing.T) {
	for _, tc := range []struct {
		name, provider, fallback string
		allowed                  bool
	}{
		{"compatible", "fal", "fal", true},
		{"incompatible_primary", "venice", "fal", false},
		{"incompatible_fallback", "fal", "venice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizes, refunds := 0, 0
			client := New("http://127.0.0.1:18081,http://127.0.0.1:18082", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				respond := func(body string) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				}
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					if r.Header.Get("X-Quill-Video-Allowed-Providers") != "fal" {
						t.Error("missing routing constraint on authorization attempt")
					}
					if r.URL.Host == "127.0.0.1:18081" {
						return nil, &dialFailure{err: errors.New("unavailable")}
					}
					authorizes++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["provider"] != nil {
						t.Errorf("changed caller's authorization body: %#v, %v", body, err)
					}
					return respond(fmt.Sprintf(`{"data":{"authorization_id":"auth","workspace_id":"ws","api_key_hash":"hash","model":"minimax/h3-max","provider":%q,"endpoint_id":"primary","additional_cost_reservation_microdollars":500000,"route_candidates":[{"provider":%q,"endpoint_id":"fallback"}]}}`, tc.provider, tc.fallback))
				case "/internal/gateway/refund":
					refunds++
					if r.URL.Host != "127.0.0.1:18082" || r.Header.Get("X-Quill-Video-Allowed-Providers") != "" {
						t.Error("refund did not preserve authority or leaked routing header")
					}
					return respond(`{"data":{"refunded":true}}`)
				default:
					t.Errorf("unexpected call %s", r.URL.Path)
					return respond(`{}`)
				}
			})})
			ctx := WithVideoAllowedProviders(t.Context(), []string{"fal"})
			auth, job, err := client.AuthorizeVideo(ctx, "test", "minimax/h3-max", "key", strings.Repeat("a", 64), nil, 500000)
			if job != nil || authorizes != 1 {
				t.Fatalf("job=%+v authorizes=%d", job, authorizes)
			}
			if tc.allowed {
				if auth == nil || err != nil || refunds != 0 {
					t.Fatalf("compatible authorization rejected: auth=%+v err=%v refunds=%d", auth, err, refunds)
				}
			} else {
				var cp *ControlPlaneError
				if auth != nil || !errors.As(err, &cp) || cp.StatusCode != 503 || cp.Type != "video_routing_unavailable" || refunds != 1 {
					t.Fatalf("incompatible dispatch allowed: auth=%+v err=%v refunds=%d", auth, err, refunds)
				}
			}
		})
	}
}
