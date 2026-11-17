package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestNearAIPreInferenceRetriesKeepConnectionsBound(t *testing.T) {
	for _, test := range []struct {
		name                                string
		rejected, wantConnections, wantPost int
		cancel, badFetch, badDials, badPost bool
		badDialFirst, partialStream         bool
		wantError                           bool
	}{
		{name: "first verified", wantConnections: 1, wantPost: 1},
		{name: "second verified", rejected: 1, wantConnections: 2, wantPost: 1},
		{name: "third verified", rejected: 2, wantConnections: 3, wantPost: 1},
		{name: "sixth verified", rejected: 5, wantConnections: 6, wantPost: 1},
		{name: "last attempt verified", rejected: nearAIAttestationAttempts - 1, wantConnections: nearAIAttestationAttempts, wantPost: 1},
		{name: "all unreviewed", rejected: nearAIAttestationAttempts + 3, wantConnections: nearAIAttestationAttempts, wantError: true},
		{name: "cancelled verification", cancel: true, rejected: 1, wantConnections: 1, wantError: true},
		{name: "authentication failure", badFetch: true, wantConnections: 1, wantError: true},
		{name: "connection changed", badDials: true, wantConnections: 1, wantError: true},
		{name: "never retry inference", badPost: true, wantConnections: 1, wantPost: 1, wantError: true},
		{name: "unreachable first address", badDialFirst: true, wantConnections: 2, wantPost: 1},
		{name: "never retry partial stream", partialStream: true, wantConnections: 1, wantPost: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := newNearAI("test-key")
			var logs []string
			client.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
			var connections []*nearAITestConnection
			var nonces []string
			var sharedDeadline time.Time
			posts, verified := 0, 0
			client.openConnection = func(domain string, attempt int) (nearAIConnection, *http.Client, error) {
				if attempt != len(connections) {
					t.Fatal("address-selection attempt did not advance")
				}
				if domain != "glm-5-3-flash.completions.near.ai" {
					t.Fatalf("unexpected domain: %s", domain)
				}
				for _, previous := range connections {
					if !previous.closed.Load() {
						t.Fatal("failed connection was retained on retry")
					}
				}
				index := len(connections) + 1
				conn := &nearAITestConnection{fingerprint: fmt.Sprintf("%064x", index), dials: 1}
				if test.badDials {
					conn.dials = 2
				}
				connections = append(connections, conn)
				httpc := &http.Client{Transport: nearAIRoundTripper(func(req *http.Request) (*http.Response, error) {
					status, payload := http.StatusOK, `{"evidence":true}`
					if req.Method == http.MethodGet {
						deadline, ok := req.Context().Deadline()
						if !ok || (!sharedDeadline.IsZero() && !deadline.Equal(sharedDeadline)) {
							t.Fatal("retry reset or removed the shared attestation deadline")
						}
						sharedDeadline = deadline
						nonce := req.URL.Query().Get("nonce")
						if len(nonce) != 64 {
							t.Fatal("invalid nonce")
						}
						for _, previous := range nonces {
							if previous == nonce {
								t.Fatal("retry reused challenge nonce")
							}
						}
						nonces = append(nonces, nonce)
						if test.badDialFirst && index == 1 {
							return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unreachable")}
						}
						if test.badFetch {
							status = http.StatusUnauthorized
						}
					} else {
						posts++
						if req.Method != http.MethodPost || verified != index || conn.closed.Load() {
							t.Fatal("inference escaped its verified connection")
						}
						payload = "data: {\"id\":\"test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
						if test.badPost {
							status, payload = http.StatusBadGateway, `{"error":{"message":"inference failed"}}`
						}
					}
					var body io.Reader = strings.NewReader(payload)
					if test.partialStream && req.Method == http.MethodPost {
						body = io.MultiReader(strings.NewReader(strings.TrimSuffix(payload, "data: [DONE]\n\n")), nearAIErrorReader{})
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(body), Request: req}, nil
				})}
				return conn, httpc, nil
			}
			client.verifyEvidence = func(_ context.Context, evidence *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error) {
				index := len(connections)
				if posts != 0 || evidence.TLSFingerprint != connections[index-1].fingerprint ||
					evidence.Nonce != nonces[index-1] || evidence.Model != "z-ai/glm-5.3-flash" {
					t.Fatal("evidence was not bound to this attempt before inference")
				}
				if test.cancel {
					cancel()
				}
				if index <= test.rejected {
					return nil, errors.New("unreviewed deployment")
				}
				verified = index
				return &nearAIVerificationResult{VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
			}
			var out bytes.Buffer
			err := client.InvokeStreaming(ctx, &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
				&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}}}, &out)
			if (err != nil) != test.wantError || len(connections) != test.wantConnections || posts != test.wantPost {
				t.Fatalf("err=%v connections=%d posts=%d", err, len(connections), posts)
			}
			for _, conn := range connections {
				if !conn.closed.Load() {
					t.Fatal("connection not closed after completion")
				}
			}
			if test.wantPost == 0 && out.Len() != 0 {
				t.Fatal("unverified attempt emitted response bytes")
			}
			// Each refused attempt keeps its reason and gains its attempt number.
			var wantLogs []string
			if test.badDialFirst {
				wantLogs = append(wantLogs, fmt.Sprintf("attempt=1/%d stage=fetch", nearAIAttestationAttempts))
			}
			for attempt := 1; attempt <= min(test.rejected, len(connections)); attempt++ {
				wantLogs = append(wantLogs, fmt.Sprintf("attempt=%d/%d stage=verify err=\"unreviewed deployment\"", attempt, nearAIAttestationAttempts))
			}
			if len(logs) != len(wantLogs) {
				t.Fatalf("attempt logs = %q, want %d lines", logs, len(wantLogs))
			}
			for index, want := range wantLogs {
				if !strings.HasPrefix(logs[index], "near-ai.attest.attempt_failed domain=\"glm-5-3-flash.completions.near.ai\" ") ||
					!strings.Contains(logs[index], want) {
					t.Fatalf("attempt log %d = %q, want %q", index, logs[index], want)
				}
			}
			if test.rejected >= nearAIAttestationAttempts {
				// Exhausting every attempt surfaces as the caller's 502.
				if status := upstreamerror.Parse(err).Status; status != http.StatusBadGateway {
					t.Fatalf("exhausted attestation status = %d, want 502", status)
				}
				if !strings.Contains(err.Error(), fmt.Sprintf("no verified connection after %d attempts", nearAIAttestationAttempts)) ||
					!strings.Contains(err.Error(), "unreviewed deployment") {
					t.Fatalf("exhausted attestation error = %v", err)
				}
			}
		})
	}
}

// Raising the attempt count must not raise the time spent before inference:
// every attempt runs under the request's own deadline, and the loop stops as
// soon as that deadline passes.
func TestNearAIAttestationRetriesStopAtRequestDeadline(t *testing.T) {
	for _, test := range []struct {
		name            string
		blockStage      string // attempt 2 waits here until the deadline passes
		expired         bool
		wantConnections int
	}{
		{name: "deadline during verification", blockStage: "verify", wantConnections: 2},
		{name: "deadline during attestation fetch", blockStage: "fetch", wantConnections: 2},
		{name: "deadline before first attempt", expired: true, wantConnections: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			timeout := time.Second
			if test.expired {
				timeout = -time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			requestDeadline, _ := ctx.Deadline()
			client := newNearAI("test-key")
			client.logf = func(string, ...any) {}
			var connections []*nearAITestConnection
			posts := 0
			client.openConnection = func(_ string, _ int) (nearAIConnection, *http.Client, error) {
				index := len(connections) + 1
				conn := &nearAITestConnection{fingerprint: fmt.Sprintf("%064x", index), dials: 1}
				connections = append(connections, conn)
				return conn, &http.Client{Transport: nearAIRoundTripper(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodGet {
						posts++
						return nil, errors.New("prompt sent without a verified connection")
					}
					if deadline, ok := req.Context().Deadline(); !ok || !deadline.Equal(requestDeadline) {
						t.Errorf("attestation deadline = %v, want the shorter request deadline %v", deadline, requestDeadline)
					}
					if test.blockStage == "fetch" && index == 2 {
						return nil, waitForNearAITestDeadline(req.Context(), t)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"evidence":true}`)),
						Request:    req,
					}, nil
				})}, nil
			}
			client.verifyEvidence = func(verifyCtx context.Context, _ *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error) {
				if test.blockStage == "verify" && len(connections) == 2 {
					return nil, fmt.Errorf("near-ai: attestation sidecar unavailable: %w", waitForNearAITestDeadline(verifyCtx, t))
				}
				return nil, errors.New("unreviewed deployment")
			}
			err := client.InvokeStreaming(ctx, &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
				&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}}}, io.Discard)
			if !errors.Is(err, context.DeadlineExceeded) || len(connections) != test.wantConnections || posts != 0 {
				t.Fatalf("err=%v connections=%d posts=%d", err, len(connections), posts)
			}
			for _, conn := range connections {
				if !conn.closed.Load() {
					t.Fatal("connection not closed after the deadline")
				}
			}
		})
	}
}

// waitForNearAITestDeadline blocks like a slow upstream until the attempt's
// context ends, and fails fast if that context outlives the request deadline.
func waitForNearAITestDeadline(ctx context.Context, t *testing.T) error {
	t.Helper()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		t.Error("attestation attempt outlived the request deadline")
		return context.DeadlineExceeded
	}
}

type nearAIErrorReader struct{}

func (nearAIErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestNearAIAddressRotationOnlyUsesDNSIPs(t *testing.T) {
	for attempt, want := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.1"} {
		for _, addresses := range [][]string{
			{"192.0.2.2", "192.0.2.1", "192.0.2.2"},
			{"192.0.2.1", "192.0.2.2", "not-an-ip"},
		} {
			got, err := nearAIAddressForAttempt(addresses, attempt)
			if err != nil || got != want {
				t.Fatalf("attempt=%d got=%q err=%v want=%q", attempt, got, err, want)
			}
		}
	}
	for _, addresses := range [][]string{nil, {"attacker.invalid"}, {"127.0.0.1:443"}} {
		if _, err := nearAIAddressForAttempt(addresses, 0); err == nil {
			t.Fatal("invalid DNS addresses accepted")
		}
	}
}
