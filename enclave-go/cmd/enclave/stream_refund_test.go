package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestPreHeaderFailureRefundIsCorrelatedAndRecoverable(t *testing.T) {
	for _, refundFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "queued"}[refundFails], func(t *testing.T) {
			t.Setenv("QUILL_USAGE_HEARTBEAT", "on")
			t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
			q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4)}
			original := settlementRetries
			settlementRetries = q
			t.Cleanup(func() { settlementRetries = original })
			const trace = "rlog_00112233445566778899aabbccddeeff"
			var refunds int
			gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == trustedrouter.HeartbeatPath {
					return nil, context.DeadlineExceeded
				}
				if r.URL.Path != "/internal/gateway/refund" {
					t.Fatalf("unexpected billing path %s", r.URL.Path)
				}
				refunds++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["gateway_request_id"] != trace || body["error_type"] != "heartbeat_unavailable" {
					t.Fatalf("refund = %#v", body)
				}
				if body["selected_endpoint"] != "anthropic/test" || body["selected_model"] != "model" {
					t.Fatalf("refund lost selected route: %#v", body)
				}
				if refundFails {
					return nil, context.DeadlineExceeded
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"disposition":"finalized","finalization_outcome":"refunded","cost_microdollars":0}}`)), Request: r}, nil
			})
			provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
				upstreamerror.Open(out)
				_, err := io.WriteString(out, providerStreamTestResponse)
				return err
			}}
			var out synchronizedBuffer
			auth := stageDStreamingAuthorization()
			auth.EndpointID, auth.Model = "initial/endpoint", "initial/model"
			serveStreaming(t.Context(), &out, provider, &types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, auth, nil, time.Now(), nil, "chat.completions", trace, "model")
			if !strings.Contains(out.String(), "503 Service Unavailable") || strings.Contains(out.String(), "200 OK") || refunds != 1 {
				t.Fatalf("refunds=%d wire=%s", refunds, out.String())
			}
			if refundFails {
				select {
				case job := <-q.jobs:
					if job.kind != "refund" || job.requestLogID != trace || job.frozen == nil || job.frozenErr != nil {
						t.Fatalf("invalid durable refund: kind=%s freeze_error=%v", job.kind, job.frozenErr)
					}
				default:
					t.Fatal("failed refund not queued")
				}
			} else if len(q.jobs) != 0 {
				t.Fatal("accepted refund retried")
			}
		})
	}
}

func TestStreamHeaderWriteFailureRefundsBeforeAnyOutput(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	var refunds int
	gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/internal/gateway/refund" {
			t.Fatalf("unexpected billing path %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["error_type"] != "client_write_failed" || body["error_status"] != float64(499) {
			t.Fatalf("refund = %#v", body)
		}
		refunds++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"disposition":"finalized","finalization_outcome":"refunded","cost_microdollars":0}}`)), Request: r}, nil
	})
	provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		upstreamerror.Open(out)
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	serveStreaming(t.Context(), failingWriter{err: io.ErrClosedPipe}, provider, &types.OpenAIChatRequest{Model: "model", Stream: true}, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: "model", EndpointID: "anthropic/test"}}, gateway, stageDStreamingAuthorization(), nil, time.Now(), nil, "chat.completions", "rlog_00112233445566778899aabbccddeeff", "model")
	if refunds != 1 {
		t.Fatalf("refund count = %d, want 1", refunds)
	}
}

func TestStreamRefundKeepsEarlierTerminalWinner(t *testing.T) {
	gateway := stageDStreamingGateway(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"disposition":"reaped_snapshot","finalization_outcome":"reaped_snapshot","already_settled":true,"cost_microdollars":256625}}`)), Request: r}, nil
	})
	result := refundFailedStream(t.Context(), gateway, stageDStreamingAuthorization(), "rlog_00112233445566778899aabbccddeeff", 503, "heartbeat_unavailable", 1, nil)
	if !result.HasCost() || result.CostMicrodollars != 256625 || !result.AlreadySettled {
		t.Fatalf("terminal winner changed: %#v", result)
	}
}
