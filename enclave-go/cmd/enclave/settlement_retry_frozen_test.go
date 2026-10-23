package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const frozenRetryRequestLogID = "rlog_0123456789abcdef0123456789abcdef"

// frozenRetryCapture is one control-plane request as the router received it.
type frozenRetryCapture struct {
	endpoint int
	path     string
	body     string
	header   http.Header
}

// frozenRetryGateway is a two-authority control plane that records every
// settle and refund, so a test can see which authority got which bytes.
func frozenRetryGateway(t *testing.T) (*trustedrouter.Client, func() []frozenRetryCapture) {
	t.Helper()
	var mu sync.Mutex
	var captured []frozenRetryCapture
	handler := func(endpoint int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
			}
			mu.Lock()
			captured = append(captured, frozenRetryCapture{endpoint: endpoint, path: r.URL.Path, body: string(raw), header: r.Header.Clone()})
			mu.Unlock()
			_, _ = io.WriteString(w, `{"data":{"cost_microdollars":15,"disposition":"finalized"}}`)
		})
	}
	primary := httptest.NewServer(handler(0))
	t.Cleanup(primary.Close)
	secondary := httptest.NewServer(handler(1))
	t.Cleanup(secondary.Close)
	gateway := trustedrouter.New(primary.URL+","+secondary.URL, "internal-test", &http.Client{})
	if err := gateway.ConfigurationError(); err != nil {
		t.Fatal(err)
	}
	return gateway, func() []frozenRetryCapture {
		mu.Lock()
		defer mu.Unlock()
		return append([]frozenRetryCapture(nil), captured...)
	}
}

func frozenRetryPrivateAuthorization(endpoint int, pinned bool) *trustedrouter.Authorization {
	return &trustedrouter.Authorization{
		AuthorizationID:         "auth_frozen_retry",
		WorkspaceID:             "workspace-private",
		APIKeyHash:              "key-hash-private",
		Model:                   "openai/gpt-4o-mini",
		UpstreamModel:           "gpt-4o-mini-upstream",
		EndpointID:              "openai/gpt-4o-mini@openai/prepaid",
		Provider:                "openai",
		UsageType:               "Credits",
		BYOKSecretRef:           "byok-private",
		RouteCandidates:         []trustedrouter.RouteCandidate{{Provider: "openai", BYOKSecretRef: "byok-private"}},
		BroadcastDestinations:   []trustedrouter.BroadcastDestination{{ID: "broadcast-private"}},
		Tags:                    types.TagMap{"tag": "private"},
		RouteType:               "chat.completions",
		ControlPlaneEndpoint:    endpoint,
		ControlPlaneEndpointSet: pinned,
	}
}

func frozenRetryPrivateUsage() trustedrouter.Usage {
	return trustedrouter.Usage{
		RequestID:      "chatcmpl_frozen",
		InputTokens:    120,
		OutputTokens:   34,
		ElapsedSeconds: 1.25,
		FinishReason:   "stop",
		RouteType:      "chat.completions",
		SelectedModel:  "openai/gpt-4o-mini",
		ServiceTier:    "default",
		User:           "user-private",
		SessionID:      "session-private",
		Trace:          map[string]any{"trace_private": "trace-value-private"},
		Metadata:       map[string]any{"metadata_private": "metadata-value-private"},
		App:            "app-private",
		HTTPReferer:    "https://referer-private.example",
		AppCategories:  []string{"category-private"},
	}
}

func frozenRetryCases() []struct {
	name         string
	job          func() settlementRetryJob
	wantEndpoint int
	wantPath     string
	wantBody     string
} {
	reported := 15
	clientContext := &types.ClientContext{V: 1, Source: "tr", Attempt: intPtrMainTest(2)}
	return []struct {
		name         string
		job          func() settlementRetryJob
		wantEndpoint int
		wantPath     string
		wantBody     string
	}{
		{
			// settleForUsageResponse: a priced body response whose settle was rejected.
			name: "body_response",
			job: func() settlementRetryJob {
				return settlementRetryJob{
					cause:     &trustedrouter.ControlPlaneError{Path: "/internal/gateway/settle", StatusCode: http.StatusBadRequest},
					trGateway: nil, authorization: frozenRetryPrivateAuthorization(1, true), usage: frozenRetryPrivateUsage(),
					reportedCost: &reported, requestLogID: frozenRetryRequestLogID, clientContext: clientContext,
				}
			},
			wantEndpoint: 1,
			wantPath:     "/internal/gateway/settle",
			wantBody:     `{"actual_input_tokens":120,"actual_output_tokens":34,"app":"attested-gateway","authorization_id":"auth_frozen_retry","client":{"attempt":2,"source":"tr","v":1},"elapsed_seconds":1.25,"finish_reason":"stop","gateway_request_id":"rlog_0123456789abcdef0123456789abcdef","request_id":"chatcmpl_frozen","route_type":"chat.completions","selected_endpoint":"openai/gpt-4o-mini@openai/prepaid","selected_model":"openai/gpt-4o-mini","service_tier":"default","status":"success","streamed":false,"usage_estimated":false}`,
		},
		{
			// serveStreaming: a terminal stream settle that failed with a 5xx,
			// from an authorization that was never pinned to an authority.
			name: "stream_settle_failure",
			job: func() settlementRetryJob {
				usage := frozenRetryPrivateUsage()
				usage.Streamed = true
				usage.FinishReason = ""
				usage.SelectedModel = ""
				usage.SelectedEndpoint = "openai/gpt-4o-mini@openai/fallback"
				usage.FirstTokenSeconds = 0.4
				usage.ReasoningTokens = 9
				usage.PriceTierInputTokens = 100
				usage.CacheReadInputTokens = 11
				usage.CacheCreationInputTokens = 5
				usage.AdditionalCostMicrodollars = 77
				usage.RouteFallbacks = 2
				usage.RouteFailures = []string{"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10"}
				return settlementRetryJob{
					cause:     &trustedrouter.ControlPlaneError{Path: "/internal/gateway/settle", StatusCode: http.StatusServiceUnavailable},
					trGateway: nil, authorization: frozenRetryPrivateAuthorization(0, false), usage: usage,
					requestLogID: frozenRetryRequestLogID, clientContext: clientContext,
				}
			},
			wantEndpoint: 0,
			wantPath:     "/internal/gateway/settle",
			wantBody:     `{"actual_input_tokens":120,"actual_output_tokens":34,"additional_cost_microdollars":77,"app":"attested-gateway","authorization_id":"auth_frozen_retry","cache_creation_input_tokens":5,"cache_read_input_tokens":11,"client":{"attempt":2,"source":"tr","v":1},"elapsed_seconds":1.25,"finish_reason":"stop","first_token_seconds":0.4,"gateway_request_id":"rlog_0123456789abcdef0123456789abcdef","price_tier_input_tokens":100,"reasoning_tokens":9,"request_id":"chatcmpl_frozen","route_failures":["f1","f2","f3","f4","f5","f6","f7","f8"],"route_fallbacks":2,"route_type":"chat.completions","selected_endpoint":"openai/gpt-4o-mini@openai/fallback","selected_model":"openai/gpt-4o-mini","service_tier":"default","status":"success","streamed":true,"usage_estimated":false}`,
		},
		{
			// Stage D BeforeTerminal: the bounded settle wait expired.
			name: "stage_d_before_terminal",
			job: func() settlementRetryJob {
				auth := stageDStreamingAuthorization()
				auth.ControlPlaneEndpoint, auth.ControlPlaneEndpointSet = 0, true
				auth.CandidateCostReporting = true
				usage := frozenRetryPrivateUsage()
				usage.Streamed = true
				usage.UsageEstimated = true
				usage.SelectedEndpoint = "anthropic/test"
				usage.SelectedModel = "model"
				return settlementRetryJob{
					cause:     context.DeadlineExceeded,
					trGateway: nil, authorization: auth, usage: usage,
					reportedCost: &reported, requestLogID: frozenRetryRequestLogID, clientContext: clientContext,
				}
			},
			wantEndpoint: 0,
			wantPath:     "/internal/gateway/settle",
			wantBody:     `{"actual_input_tokens":120,"actual_output_tokens":34,"app":"attested-gateway","authorization_id":"gwa-stage-d-fixture","client":{"attempt":2,"source":"tr","v":1},"elapsed_seconds":1.25,"finish_reason":"stop","gateway_request_id":"rlog_0123456789abcdef0123456789abcdef","request_id":"chatcmpl_frozen","route_type":"chat.completions","selected_endpoint":"anthropic/test","selected_model":"model","service_tier":"default","status":"success","streamed":true,"usage_estimated":true}`,
		},
		{
			name: "videos",
			job: func() settlementRetryJob {
				usage := frozenRetryPrivateUsage()
				usage.RouteType = "videos"
				usage.VideoInputMode = "text"
				usage.VideoDurationSeconds = 8
				usage.VideoResolution = "720p"
				usage.VideoAspectRatio = "16:9"
				usage.VideoGenerateAudio = true
				return settlementRetryJob{
					cause:     io.ErrUnexpectedEOF,
					trGateway: nil, authorization: frozenRetryPrivateAuthorization(1, true), usage: usage,
					requestLogID: frozenRetryRequestLogID,
				}
			},
			wantEndpoint: 1,
			wantPath:     "/internal/gateway/settle",
			wantBody:     `{"actual_input_tokens":120,"actual_output_tokens":34,"app":"attested-gateway","authorization_id":"auth_frozen_retry","elapsed_seconds":1.25,"finish_reason":"stop","gateway_request_id":"rlog_0123456789abcdef0123456789abcdef","request_id":"chatcmpl_frozen","route_type":"videos","selected_endpoint":"openai/gpt-4o-mini@openai/prepaid","selected_model":"openai/gpt-4o-mini","service_tier":"default","status":"success","streamed":false,"usage_estimated":false,"video_aspect_ratio":"16:9","video_duration_seconds":8,"video_generate_audio":true,"video_input_mode":"text","video_resolution":"720p"}`,
		},
		{
			name: "refund",
			job: func() settlementRetryJob {
				return settlementRetryJob{
					cause:     syscall.ECONNRESET,
					trGateway: nil, authorization: frozenRetryPrivateAuthorization(1, true), kind: "refund",
					refundStatus: 502, refundType: "provider_error", refundElapsed: 0.25,
					refundMetadata: map[string]any{"refund_metadata_private": "refund-value-private"},
					requestLogID:   frozenRetryRequestLogID, clientContext: clientContext,
				}
			},
			wantEndpoint: 1,
			wantPath:     "/internal/gateway/refund",
			wantBody:     `{"app":"attested-gateway","authorization_id":"auth_frozen_retry","client":{"attempt":2,"source":"tr","v":1},"elapsed_seconds":0.25,"error_status":502,"error_type":"provider_error","gateway_request_id":"rlog_0123456789abcdef0123456789abcdef","route_type":"chat.completions","selected_endpoint":"openai/gpt-4o-mini@openai/prepaid","selected_model":"openai/gpt-4o-mini","streamed":true}`,
		},
		{
			// Defaults: no status, no error type, no elapsed time, an unpinned
			// authorization and a request log id that is not sent.
			name: "refund_defaults",
			job: func() settlementRetryJob {
				auth := frozenRetryPrivateAuthorization(0, false)
				auth.RouteType = ""
				return settlementRetryJob{
					cause:     context.Canceled,
					trGateway: nil, authorization: auth, kind: "refund",
					refundMetadata: map[string]any{"refund_metadata_private": "refund-value-private"},
					requestLogID:   "not-a-request-log-id",
				}
			},
			wantEndpoint: 0,
			wantPath:     "/internal/gateway/refund",
			wantBody:     `{"app":"attested-gateway","authorization_id":"auth_frozen_retry","elapsed_seconds":0.001,"error_status":502,"error_type":"provider_error","selected_endpoint":"openai/gpt-4o-mini@openai/prepaid","selected_model":"openai/gpt-4o-mini","streamed":true}`,
		},
	}
}

// A queued retry sends exactly the bytes the enclave sent before settle and
// refund terminals were frozen: these bodies were captured from the retry
// queue on the commit before the refactor.
func TestSettlementRetrySendsGoldenFrozenBytes(t *testing.T) {
	for _, tc := range frozenRetryCases() {
		t.Run(tc.name, func(t *testing.T) {
			gateway, captured := frozenRetryGateway(t)
			q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 2), maxAttempts: 1}
			job := tc.job()
			job.trGateway = gateway
			if !q.Enqueue(job) {
				t.Fatal("retry was not accepted")
			}
			queued := <-q.jobs
			q.process(t.Context(), queued)
			got := captured()
			if len(got) != 1 {
				t.Fatalf("control-plane requests = %d, want 1", len(got))
			}
			sent := got[0]
			if sent.path != tc.wantPath || sent.endpoint != tc.wantEndpoint {
				t.Fatalf("sent %s to authority %d, want %s to %d", sent.path, sent.endpoint, tc.wantPath, tc.wantEndpoint)
			}
			if sent.body != tc.wantBody {
				t.Fatalf("retry body changed\n got: %s\nwant: %s", sent.body, tc.wantBody)
			}
			for _, private := range []string{"private", `"user"`, `"session_id"`, `"trace"`, `"metadata"`, "http_referer", "app_categories", "cache_affinity"} {
				if strings.Contains(sent.body, private) {
					t.Fatalf("retry body carries %q: %s", private, sent.body)
				}
			}
			for _, header := range []string{"X-TR-Settlement-Mode", "X-TR-Settlement-Shadow", "X-TR-Settlement-Shadow-Policy", "X-TR-Boot-Auth"} {
				if value := sent.header.Get(header); value != "" {
					t.Fatalf("retry sent %s", header)
				}
			}
			if sent.header.Get("Content-Type") != "application/json" || sent.header.Get("x-trustedrouter-internal-token") == "" {
				t.Fatal("retry lost its control-plane headers")
			}
		})
	}
}
