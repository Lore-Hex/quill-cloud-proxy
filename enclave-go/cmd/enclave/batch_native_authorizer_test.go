package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	batchapi "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestBatchNativeHandlePersistsOnlySettlementAndAttributionFields(t *testing.T) {
	t.Parallel()

	authorization := &trustedrouter.Authorization{
		AuthorizationID: "auth-1",
		WorkspaceID:     "workspace-sensitive",
		APIKeyHash:      "key-hash-sensitive",
		Model:           "openai/gpt-5.5",
		EndpointID:      "openai-endpoint",
		BYOKEncryptedSecret: &byokcache.EncryptedSecretEnvelope{
			Ciphertext: "byok-sensitive",
		},
		BroadcastDestinations: []trustedrouter.BroadcastDestination{{
			Endpoint: "https://broadcast-sensitive.example",
		}},
		CustomModel: &trustedrouter.CustomModel{HiddenPrompt: "hidden-prompt-sensitive"},
	}
	encoded, err := encodeBatchNativeHandle(
		authorization,
		123,
		nativeBatchChatRoute,
		batchNativeAttribution{
			User:      "matter-user",
			SessionID: "matter-session",
			Trace:     map[string]any{"case": "trace-1"},
			Metadata:  map[string]any{"team": "legal"},
		},
	)
	if err != nil {
		t.Fatalf("encodeBatchNativeHandle: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte("workspace-sensitive"),
		[]byte("key-hash-sensitive"),
		[]byte("byok-sensitive"),
		[]byte("broadcast-sensitive"),
		[]byte("hidden-prompt-sensitive"),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("sensitive authorization field persisted: %q", forbidden)
		}
	}

	decoded, err := decodeBatchNativeHandle(batchNativeAuthorization(encoded))
	if err != nil {
		t.Fatalf("decodeBatchNativeHandle: %v", err)
	}
	frozen := decoded.authorization()
	if frozen.AuthorizationID != "auth-1" || frozen.Model != "openai/gpt-5.5" ||
		frozen.EndpointID != "openai-endpoint" || frozen.RouteType != nativeBatchChatRoute {
		t.Fatalf("frozen authorization = %#v", frozen)
	}
	if decoded.EstimatedInputTokens != 123 {
		t.Fatalf("estimated input tokens = %d", decoded.EstimatedInputTokens)
	}
	if decoded.User != "matter-user" || decoded.SessionID != "matter-session" ||
		decoded.Trace["case"] != "trace-1" || decoded.Metadata["team"] != "legal" {
		t.Fatalf("attribution = %#v", decoded)
	}
}

func batchNativeAuthorization(handle []byte) batchapi.NativeAuthorization {
	return batchapi.NativeAuthorization{Handle: json.RawMessage(handle)}
}

func TestNativeRoutesUseTheLiveInferenceProviderModelResolver(t *testing.T) {
	t.Parallel()

	routes := nativeRoutes(&trustedrouter.Authorization{
		RouteCandidates: []trustedrouter.RouteCandidate{
			{
				Provider: "openai", Model: "openai/gpt-5.5",
				UpstreamModel: "openai/gpt-5.5", UsageType: "Credits",
			},
			{
				Provider: "parasail", Model: "z-ai/glm-5.2",
				UpstreamModel: "parasail-glm-52", UsageType: "Credits",
			},
		},
	})
	if len(routes) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	if routes[0].UpstreamModel != "gpt-5.5" {
		t.Fatalf("OpenAI upstream model = %q", routes[0].UpstreamModel)
	}
	if routes[1].UpstreamModel != "parasail-glm-52" {
		t.Fatalf("Parasail upstream model = %q", routes[1].UpstreamModel)
	}
}

func TestBatchNativeAuthorizePreservesOrdinaryBYOKRouting(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: batchRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read authorize: %v", err)
		}
		var payload map[string]any
		if json.Unmarshal(body, &payload) != nil {
			t.Fatalf("authorize body = %s", body)
		}
		provider, _ := payload["provider"].(map[string]any)
		if usage, present := provider["usage"]; present {
			t.Fatalf("native authorizer overrode ordinary routing with provider.usage=%v", usage)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"data":{"authorization_id":"auth-byok","model":"openai/gpt-5.5","endpoint_id":"openai/gpt-5.5@openai/byok","provider":"openai","usage_type":"BYOK","limit_usage_type":"BYOK","native_batch_eligible":false,"route_candidates":[{"endpoint_id":"openai/gpt-5.5@openai/byok","model":"openai/gpt-5.5","upstream_model":"gpt-5.5","provider":"openai","usage_type":"BYOK"}]}}`,
			)),
		}, nil
	})}
	authorizer := &batchNativeAuthorizer{
		gateway: trustedrouter.New("https://control.example", "internal", httpClient),
	}
	authorized, err := authorizer.Authorize(
		t.Context(), strings.Repeat("a", 64), "/v1/chat/completions",
		[]byte(`{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"PONG"}]}`),
		"tr-native-batch:test:0",
	)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authorized.NativeBatchEligible || len(authorized.Routes) != 1 ||
		authorized.Routes[0].UsageType != "BYOK" {
		t.Fatalf("authorization = %#v", authorized)
	}
}

func TestBatchNativeAuthorizeClassifiesAmbiguousControlPlaneOutcomes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		status    int
		retryable bool
	}{
		{name: "bad request", status: http.StatusBadRequest},
		{name: "idempotency conflict", status: http.StatusConflict},
		{name: "rate limited", status: http.StatusTooManyRequests, retryable: true},
		{name: "server unavailable", status: http.StatusServiceUnavailable, retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{Transport: batchRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Header:     make(http.Header),
					Body: io.NopCloser(strings.NewReader(
						`{"error":{"message":"authorization failed","type":"authorization_error"}}`,
					)),
				}, nil
			})}
			authorizer := &batchNativeAuthorizer{
				gateway: trustedrouter.New("https://control.example", "internal", httpClient),
			}
			_, err := authorizer.Authorize(
				t.Context(), strings.Repeat("a", 64), "/v1/chat/completions",
				[]byte(`{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"PONG"}]}`),
				"tr-native-batch:test:0",
			)
			if err == nil {
				t.Fatal("Authorize unexpectedly succeeded")
			}
			if errors.Is(err, batchapi.ErrNativeAuthorizationRetryable) != test.retryable {
				t.Fatalf("error = %v, retryable = %t", err, test.retryable)
			}
		})
	}
}

func TestBatchNativeSettlePreservesEncryptedAttribution(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: batchRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/internal/gateway/settle" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read settle: %v", err)
		}
		for _, expected := range [][]byte{
			[]byte(`"user":"matter-user"`),
			[]byte(`"session_id":"matter-session"`),
			[]byte(`"trace":{"case":"trace-1"}`),
			[]byte(`"metadata":{"team":"legal"}`),
		} {
			if !bytes.Contains(body, expected) {
				t.Fatalf("settle lost attribution %s: %s", expected, body)
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"data":{"settled":true,"cost_microdollars":9,"generation_id":"gen-1","provider":"openai","region":"us-east4"}}`,
			)),
		}, nil
	})}
	handle, err := json.Marshal(batchNativeAuthorizationHandle{
		AuthorizationID: "auth-1",
		Model:           "openai/gpt-5.5",
		EndpointID:      "openai-endpoint",
		RouteType:       nativeBatchChatRoute,
		User:            "matter-user",
		SessionID:       "matter-session",
		Trace:           map[string]any{"case": "trace-1"},
		Metadata:        map[string]any{"team": "legal"},
	})
	if err != nil {
		t.Fatalf("marshal handle: %v", err)
	}
	authorizer := &batchNativeAuthorizer{
		gateway: trustedrouter.New("https://control.example", "internal", httpClient),
	}
	settled, err := authorizer.Settle(
		t.Context(),
		batchNativeAuthorization(handle),
		batchapi.NativeUsage{
			InputTokens: 1,
			Route: batchapi.NativeRoute{
				Provider: "openai", EndpointID: "openai-endpoint", Model: "openai/gpt-5.5",
			},
		},
	)
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if settled.GenerationID != "gen-1" || settled.Provider != "openai" ||
		settled.Region != "us-east4" || settled.CostMicrodollars != 9 {
		t.Fatalf("settled usage = %#v", settled)
	}
}

func TestBatchNativeSettleClassifiesTerminalControlPlaneErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		terminal bool
	}{
		{name: "bad request", status: http.StatusBadRequest, terminal: true},
		{name: "unauthorized", status: http.StatusUnauthorized, terminal: true},
		{name: "conflict", status: http.StatusConflict},
		{name: "rate limited", status: http.StatusTooManyRequests},
		{name: "server error", status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{Transport: batchRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/internal/gateway/settle" {
					t.Fatalf("path = %q", request.URL.Path)
				}
				return &http.Response{
					StatusCode: test.status,
					Header:     make(http.Header),
					Body: io.NopCloser(strings.NewReader(
						`{"error":{"message":"settlement rejected","type":"settlement_error"}}`,
					)),
				}, nil
			})}
			authorizer := &batchNativeAuthorizer{
				gateway: trustedrouter.New("https://control.example", "internal", httpClient),
			}
			handle, err := json.Marshal(batchNativeAuthorizationHandle{
				AuthorizationID: "auth-1",
				Model:           "openai/gpt-5.5",
				EndpointID:      "openai-endpoint",
				RouteType:       nativeBatchChatRoute,
			})
			if err != nil {
				t.Fatalf("marshal handle: %v", err)
			}
			_, err = authorizer.Settle(
				t.Context(), batchNativeAuthorization(handle), batchapi.NativeUsage{
					InputTokens: 1,
					Route: batchapi.NativeRoute{
						Provider: "openai", EndpointID: "openai-endpoint", Model: "openai/gpt-5.5",
					},
				},
			)
			if err == nil {
				t.Fatal("Settle unexpectedly succeeded")
			}
			if errors.Is(err, batchapi.ErrNativeSettlementRejected) != test.terminal {
				t.Fatalf("error = %v, terminal = %t", err, test.terminal)
			}
		})
	}
}

func TestBatchNativeSettleDoesNotTreatAmbiguousReplayAsRefund(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: batchRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"data":{"settled":false,"already_settled":true}}`,
			)),
		}, nil
	})}
	handle, err := json.Marshal(batchNativeAuthorizationHandle{
		AuthorizationID: "auth-ambiguous",
		Model:           "openai/gpt-5.5",
		EndpointID:      "openai-endpoint",
		RouteType:       nativeBatchChatRoute,
	})
	if err != nil {
		t.Fatalf("marshal handle: %v", err)
	}
	authorizer := &batchNativeAuthorizer{
		gateway: trustedrouter.New("https://control.example", "internal", httpClient),
	}
	_, err = authorizer.Settle(
		t.Context(), batchNativeAuthorization(handle), batchapi.NativeUsage{
			InputTokens: 1,
			Route: batchapi.NativeRoute{
				Provider: "openai", EndpointID: "openai-endpoint", Model: "openai/gpt-5.5",
			},
		},
	)
	if !errors.Is(err, batchapi.ErrNativeSettlementPending) ||
		errors.Is(err, batchapi.ErrNativeAuthorizationRefunded) {
		t.Fatalf("error = %v", err)
	}
}

func TestBatchNativeSettleTrustsExplicitOutcomeWithoutGenerationMirror(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: batchRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"data":{"settled":true,"already_settled":true,"finalization_outcome":"settled","cost_microdollars":17,"input_tokens":7,"output_tokens":3,"provider":"openai","region":"us-east4","usage_type":"credits"}}`,
			)),
		}, nil
	})}
	handle, err := json.Marshal(batchNativeAuthorizationHandle{
		AuthorizationID: "auth-settled-no-generation",
		Model:           "openai/gpt-5.5",
		EndpointID:      "openai-endpoint",
		RouteType:       nativeBatchChatRoute,
	})
	if err != nil {
		t.Fatalf("marshal handle: %v", err)
	}
	authorizer := &batchNativeAuthorizer{
		gateway: trustedrouter.New("https://control.example", "internal", httpClient),
	}
	usage, err := authorizer.Settle(
		t.Context(), batchNativeAuthorization(handle), batchapi.NativeUsage{
			InputTokens: 1,
			Route: batchapi.NativeRoute{
				Provider: "openai", EndpointID: "openai-endpoint", Model: "openai/gpt-5.5",
			},
		},
	)
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if usage.CostMicrodollars != 17 || usage.PromptTokens != 7 || usage.CompletionTokens != 3 ||
		usage.TotalTokens != 10 || usage.Provider != "openai" || usage.GenerationID != "" {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestBatchNativeRefundDistinguishesRefundReplayFromSettlementWinner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		response       string
		alreadySettled bool
		settledUsage   batchapi.Usage
	}{
		{
			name:           "refund replay",
			response:       `{"data":{"already_settled":true,"settled":false,"finalization_outcome":"refunded","cost_microdollars":0}}`,
			alreadySettled: false,
		},
		{
			name:           "settlement won without activity mirror",
			response:       `{"data":{"already_settled":true,"settled":true,"finalization_outcome":"settled","cost_microdollars":9,"input_tokens":7,"output_tokens":3,"provider":"openai","region":"us-east4","usage_type":"credits"}}`,
			alreadySettled: true,
			settledUsage: batchapi.Usage{
				PromptTokens:     7,
				CompletionTokens: 3,
				TotalTokens:      10,
				CostMicrodollars: 9,
				Cost:             0.000009,
				Provider:         "openai",
				Region:           "us-east4",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{Transport: batchRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/internal/gateway/refund" {
					t.Fatalf("path = %q", request.URL.Path)
				}
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatalf("read refund: %v", err)
				}
				if !bytes.Contains(body, []byte(`"route_type":"batch.native.chat.completions"`)) {
					t.Fatalf("refund lost route binding: %s", body)
				}
				for _, expected := range [][]byte{
					[]byte(`"user":"matter-user"`),
					[]byte(`"session_id":"matter-session"`),
					[]byte(`"trace":{"case":"trace-1"}`),
					[]byte(`"metadata":{"batch_native":true,"team":"legal"}`),
				} {
					if !bytes.Contains(body, expected) {
						t.Fatalf("refund lost attribution %s: %s", expected, body)
					}
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(test.response)),
				}, nil
			})}

			client := trustedrouter.New("https://control.example", "internal", httpClient)
			authorizer := &batchNativeAuthorizer{gateway: client}
			handle, err := json.Marshal(batchNativeAuthorizationHandle{
				AuthorizationID: "auth-1",
				Model:           "openai/gpt-5.5",
				EndpointID:      "openai-endpoint",
				RouteType:       nativeBatchChatRoute,
				User:            "matter-user",
				SessionID:       "matter-session",
				Trace:           map[string]any{"case": "trace-1"},
				Metadata:        map[string]any{"team": "legal"},
			})
			if err != nil {
				t.Fatalf("marshal handle: %v", err)
			}
			result, err := authorizer.Refund(
				t.Context(), batchNativeAuthorization(handle), 502,
				"native_batch_expired", time.Millisecond,
			)
			if err != nil {
				t.Fatalf("Refund: %v", err)
			}
			if result.AlreadySettled != test.alreadySettled {
				t.Fatalf("AlreadySettled = %t, want %t", result.AlreadySettled, test.alreadySettled)
			}
			if result.SettledUsage != test.settledUsage {
				t.Fatalf("SettledUsage = %#v, want %#v", result.SettledUsage, test.settledUsage)
			}
		})
	}
}

type batchRoundTripFunc func(*http.Request) (*http.Response, error)

func (f batchRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
