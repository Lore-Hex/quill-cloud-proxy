package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
			// None of these failures is a routing miss, so no attempt waits.
			client.sleep = func(_ context.Context, delay time.Duration) error {
				t.Fatalf("waited %v after a failure that is not a routing miss", delay)
				return nil
			}
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
				wantLogs = append(wantLogs, "attempt=1 stage=fetch routing_miss=false")
			}
			for attempt := 1; attempt <= min(test.rejected, len(connections)); attempt++ {
				wantLogs = append(wantLogs, fmt.Sprintf("attempt=%d stage=verify routing_miss=false err=\"unreviewed deployment\"", attempt))
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
		routingMisses   bool   // every refusal is a routing miss
		timeout         time.Duration
		wantConnections int
	}{
		{name: "deadline during verification", blockStage: "verify", timeout: time.Second, wantConnections: 2},
		{name: "deadline during attestation fetch", blockStage: "fetch", timeout: time.Second, wantConnections: 2},
		{name: "deadline before first attempt", timeout: -time.Second, wantConnections: 0},
		// Attempts 1 and 2 run at once and attempt 3 after a 1s wait. The 2s wait
		// before attempt 4 is cut short by the deadline.
		{name: "deadline during routing-miss wait", routingMisses: true, timeout: 1500 * time.Millisecond, wantConnections: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			timeout := test.timeout
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
				if test.routingMisses {
					return nil, errors.New(nearAIUnpinnedInstanceRefusal)
				}
				return nil, errors.New("unreviewed deployment")
			}
			start := time.Now()
			err := client.InvokeStreaming(ctx, &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
				&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}}}, io.Discard)
			if !errors.Is(err, context.DeadlineExceeded) || len(connections) != test.wantConnections || posts != 0 {
				t.Fatalf("err=%v connections=%d posts=%d", err, len(connections), posts)
			}
			if elapsed := time.Since(start); elapsed > max(timeout, 0)+time.Second {
				t.Fatalf("attestation ran %v past a %v deadline", elapsed, timeout)
			}
			if test.routingMisses && !strings.Contains(err.Error(), "(last refusal: "+nearAIUnpinnedInstanceRefusal+")") {
				t.Fatalf("deadline error lost the last refusal: %v", err)
			}
			for _, conn := range connections {
				if !conn.closed.Load() {
					t.Fatal("connection not closed after the deadline")
				}
			}
		})
	}
}

// NEAR's front end sends every new connection, on both advertised addresses,
// to the same instance for tens of seconds at a time. Model that: the instance
// depends only on when a connection is opened. Attempts made back to back all
// land inside one ineligible stretch and fail together, so the client has to
// spread them over time to reach the pinned instance.
func TestNearAIAttestationRetriesOutlastIneligibleStretch(t *testing.T) {
	const ineligible = 600 * time.Millisecond
	client := newNearAI("test-key")
	client.logf = func(string, ...any) {}
	start := time.Now()
	var opened []time.Duration
	var connections []*nearAITestConnection
	verified := -1
	client.openConnection = func(_ string, attempt int) (nearAIConnection, *http.Client, error) {
		index := len(connections)
		opened = append(opened, time.Since(start))
		conn := &nearAITestConnection{fingerprint: fmt.Sprintf("%064x", index+1), dials: 1}
		connections = append(connections, conn)
		return conn, &http.Client{Transport: nearAIRoundTripper(func(req *http.Request) (*http.Response, error) {
			body := `{"evidence":true}`
			if req.Method != http.MethodGet {
				if verified != index || conn.closed.Load() {
					t.Fatal("inference escaped its verified connection")
				}
				body = "data: {\"id\":\"test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})}, nil
	}
	client.verifyEvidence = func(context.Context, *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error) {
		index := len(connections) - 1
		if opened[index] < ineligible {
			return nil, errors.New("near-ai: attestation refused (HTTP 403): NEAR AI workload identity is outside the pinned policy")
		}
		verified = index
		return &nearAIVerificationResult{VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
	}
	var out bytes.Buffer
	err := client.InvokeStreaming(context.Background(), &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
		&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}}}, &out)
	if err != nil {
		t.Fatalf("request failed after %d attempts opened at %v: %v", len(connections), opened, err)
	}
	if !strings.Contains(out.String(), "PONG") || verified != len(connections)-1 {
		t.Fatalf("response not served by the verified connection: verified=%d connections=%d", verified, len(connections))
	}
	for _, conn := range connections {
		if !conn.closed.Load() {
			t.Fatal("connection not closed after completion")
		}
	}
}

// On November 18 both addresses sent every new connection to the unpinned
// instance for up to 129 seconds at a stretch. Routing misses must therefore
// keep being retried until the attestation deadline, not until a count runs
// out, and often enough not to step over a short window on the pinned one.
func TestNearAIRoutingMissScheduleRunsToTheDeadline(t *testing.T) {
	var total time.Duration
	for misses := 1; misses < nearAIRoutingMissLimit; misses++ {
		delay := nearAIMissDelay(misses)
		if misses == 1 && delay != 0 {
			t.Fatalf("the first miss waits %v; the other address must be tried at once", delay)
		}
		if misses > 1 && (delay <= 0 || delay > nearAIMaxMissDelay) {
			t.Fatalf("miss %d waits %v, want (0, %v]", misses, delay, nearAIMaxMissDelay)
		}
		total += delay
	}
	if nearAIMaxMissDelay > 5*time.Second || total < nearAIAttestationTimeout {
		t.Fatalf("misses wait at most %v and %v in all; the %v deadline must end a long stretch",
			nearAIMaxMissDelay, total, nearAIAttestationTimeout)
	}
}

func TestNearAIRoutingMissesWaitAndOtherFailuresRetryAtOnce(t *testing.T) {
	seconds := func(values ...int) []time.Duration {
		out := make([]time.Duration, 0, len(values))
		for _, value := range values {
			out = append(out, time.Duration(value)*time.Second)
		}
		return out
	}
	var limitWaits []time.Duration
	for misses := 2; misses < nearAIRoutingMissLimit; misses++ {
		limitWaits = append(limitWaits, nearAIMissDelay(misses))
	}
	for _, test := range []struct {
		name string
		// One letter per attempt: M routing miss, R refusal of a pinned
		// workload, F transport failure, V verified.
		outcomes      string
		deadlineAfter time.Duration // the fake clock's attestation deadline
		wantWaits     []time.Duration
		wantErr       string
	}{
		{name: "first miss tries the other address at once", outcomes: "MV"},
		{name: "later misses back off", outcomes: "MMMMMMMV", wantWaits: seconds(1, 2, 4, 5, 5, 5)},
		{name: "pinned refusals retry at once", outcomes: "RRV"},
		{name: "transport failure after a miss retries at once", outcomes: "MMFV", wantWaits: seconds(1)},
		{name: "pinned instance refused after misses", outcomes: "MMMRRRRRR", wantWaits: seconds(1, 2),
			wantErr: fmt.Sprintf("no verified connection after %d attempts", 3+nearAIAttestationAttempts)},
		{name: "misses run until the deadline", outcomes: strings.Repeat("M", nearAIRoutingMissLimit), deadlineAfter: 30 * time.Second,
			wantWaits: seconds(1, 2, 4, 5, 5, 5, 5, 5), wantErr: "context deadline exceeded (last refusal: " + nearAIUnpinnedInstanceRefusal + ")"},
		{name: "miss limit backstops the deadline", outcomes: strings.Repeat("M", nearAIRoutingMissLimit), wantWaits: limitWaits,
			wantErr: fmt.Sprintf("no verified connection after %d attempts", nearAIRoutingMissLimit)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newNearAI("test-key")
			client.logf = func(string, ...any) {}
			var waits []time.Duration
			var slept time.Duration
			var connections []*nearAITestConnection
			client.sleep = func(ctx context.Context, delay time.Duration) error {
				for _, conn := range connections {
					if !conn.closed.Load() {
						t.Fatal("a refused connection stayed open during the wait")
					}
				}
				waits = append(waits, delay)
				if slept += delay; test.deadlineAfter > 0 && slept > test.deadlineAfter {
					return context.DeadlineExceeded
				}
				return ctx.Err()
			}
			verified, posts := -1, 0
			client.openConnection = func(_ string, attempt int) (nearAIConnection, *http.Client, error) {
				if attempt != len(connections) || attempt >= len(test.outcomes) {
					t.Fatalf("unexpected attempt %d", attempt+1)
				}
				outcome := test.outcomes[attempt]
				conn := &nearAITestConnection{fingerprint: fmt.Sprintf("%064x", attempt+1), dials: 1}
				connections = append(connections, conn)
				return conn, &http.Client{Transport: nearAIRoundTripper(func(req *http.Request) (*http.Response, error) {
					body := `{"evidence":true}`
					if req.Method == http.MethodGet && outcome == 'F' {
						return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unreachable")}
					}
					if req.Method != http.MethodGet {
						posts++
						if verified != attempt || conn.closed.Load() {
							t.Fatal("inference escaped its verified connection")
						}
						body = "data: {\"id\":\"test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}},
						Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				})}, nil
			}
			client.verifyEvidence = func(context.Context, *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error) {
				attempt := len(connections) - 1
				switch test.outcomes[attempt] {
				case 'M':
					return nil, errors.New(nearAIUnpinnedInstanceRefusal)
				case 'R':
					return nil, errors.New("near-ai: attestation refused (HTTP 403): NEAR AI deployment history is outside the reviewed policy")
				}
				verified = attempt
				return &nearAIVerificationResult{VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
			}
			var out bytes.Buffer
			err := client.InvokeStreaming(context.Background(), &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
				&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}}}, &out)
			if test.wantErr == "" {
				if err != nil || posts != 1 || !strings.Contains(out.String(), "PONG") || verified != len(test.outcomes)-1 {
					t.Fatalf("err=%v posts=%d verified=%d", err, posts, verified)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) || posts != 0 || out.Len() != 0 {
				t.Fatalf("err=%v posts=%d, want error containing %q and no prompt sent", err, posts, test.wantErr)
			}
			if fmt.Sprint(waits) != fmt.Sprint(test.wantWaits) {
				t.Fatalf("waits = %v, want %v", waits, test.wantWaits)
			}
			for _, conn := range connections {
				if !conn.closed.Load() {
					t.Fatal("connection not closed after completion")
				}
			}
		})
	}
}

// The sidecar refuses an unpinned workload with exactly this reason, as HTTP 403,
// and every other refusal with a different one. Only the former may be paced.
func TestNearAIRoutingMissComesOnlyFromTheSidecarUnpinnedRefusal(t *testing.T) {
	const reason = "NEAR AI workload identity is outside the pinned policy"
	if nearAIUnpinnedInstanceRefusal != "near-ai: attestation refused (HTTP 403): "+reason {
		t.Fatalf("refusal constant drifted: %q", nearAIUnpinnedInstanceRefusal)
	}
	verifier, err := os.ReadFile("../../sidecar/near_ai_verify.go")
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one sidecar check, the unpinned compose hash, may use the reason.
	if strings.Count(string(verifier), reason) != 1 || !strings.Contains(string(verifier), `errors.New("`+reason+`")`) {
		t.Fatal("the sidecar must use the routing-miss reason for the unpinned-workload refusal only")
	}
	sidecarMain, err := os.ReadFile("../../sidecar/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecarMain), "http.Error(w, err.Error(), http.StatusForbidden)") {
		t.Fatal("sidecar no longer returns refusal reasons as HTTP 403 bodies")
	}

	dir, err := os.MkdirTemp("", "nearsc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	var status atomic.Int32
	var body atomic.Value
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify-near-ai" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, body.Load().(string), int(status.Load()))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	previous := tinfoilSidecarSocket
	tinfoilSidecarSocket = listener.Addr().String()
	defer func() { tinfoilSidecarSocket = previous }()

	envelope := &nearAIEvidenceEnvelope{
		Model: "z-ai/glm-5.3-flash", Domain: "glm-5-3-flash.completions.near.ai",
		Nonce: strings.Repeat("a", 64), TLSFingerprint: strings.Repeat("b", 64), Evidence: []byte(`{}`),
	}
	for _, test := range []struct {
		status   int
		body     string
		wantMiss bool
	}{
		{status: http.StatusForbidden, body: reason, wantMiss: true},
		{status: http.StatusForbidden, body: "NEAR AI deployment history is outside the reviewed policy"},
		{status: http.StatusForbidden, body: "NEAR AI model quote does not bind the pinned workload compose hash"},
		{status: http.StatusForbidden, body: reason + " (extra)"},
		{status: http.StatusBadRequest, body: reason},
		{status: http.StatusServiceUnavailable, body: reason},
	} {
		status.Store(int32(test.status))
		body.Store(test.body)
		_, err := verifyNearAIEvidenceWithSidecar(context.Background(), envelope)
		if err == nil || nearAIRoutingMiss(err) != test.wantMiss {
			t.Fatalf("HTTP %d %q: err=%v routing miss=%t, want %t", test.status, test.body, err, nearAIRoutingMiss(err), test.wantMiss)
		}
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
