package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// asyncSyncPlane is a control plane for an async-negotiated chat stream whose
// async-v1 attempt is answered sync_required, so the settle goes on to the
// snapshot sync. sync answers each snapshot-sync request; legacy answers each
// settle sent without a settlement mode (in-line fallback or queued retry).
type asyncSyncPlane struct {
	mu         sync.Mutex
	syncCalls  int
	legacyHits [][]byte // body of each legacy settle
	sync       func(w http.ResponseWriter, r *http.Request, call int)
	legacy     func(w http.ResponseWriter, r *http.Request, call int)
}

func (p *asyncSyncPlane) counts() (syncCalls, legacyCalls int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.syncCalls, len(p.legacyHits)
}

// serveAsyncSyncStream authorizes an async-negotiated streaming chat request
// against plane and serves it to completion, returning the gateway's log.
func serveAsyncSyncStream(t *testing.T, plane *asyncSyncPlane) string {
	t.Helper()
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", `{"test":"router-fixture~`+base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))+`"}`)
	raw, err := os.ReadFile("../../internal/trustedrouter/testdata/async_settlement/authorize_v1_builder.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Claims   map[string]any `json:"claims"`
		Response struct {
			Data map[string]any `json:"data"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.Claims["streamed"], f.Claims["route_type"] = true, "chat.completions"
	f.Claims["iat"], f.Claims["exp"] = time.Now().Unix()-1, time.Now().Unix()+299
	claims, _ := json.Marshal(f.Claims)
	signed := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"test","typ":"tr-async-settle-v1"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	f.Response.Data["settlement_ticket"] = signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signed)))
	for k, v := range map[string]any{"credit_reservation_id": "res-v1", "workspace_id": "ws-v1", "api_key_hash": "key-v1", "invocation_nonce": "nonce-v1", "usage_type": "Credits", "model": "openai/billing-v1", "provider": "openai", "endpoint_id": "openai/billing-v1@openai/prepaid"} {
		f.Response.Data[k] = v
	}
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/gateway/authorize":
			_ = json.NewEncoder(w).Encode(f.Response)
		case r.URL.Path != "/internal/gateway/settle":
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		case r.Header.Get("X-TR-Settlement-Mode") == "async-v1":
			_, _ = io.WriteString(w, `{"data":{"acceptance":{"status":"sync_required"},"reason":"admission_stale"}}`)
		case r.Header.Get("X-TR-Settlement-Mode") == "sync":
			plane.mu.Lock()
			plane.syncCalls++
			call := plane.syncCalls
			plane.mu.Unlock()
			plane.sync(w, r.WithContext(contextUntil(r.Context(), release)), call)
		default:
			body, _ := io.ReadAll(r.Body)
			plane.mu.Lock()
			plane.legacyHits = append(plane.legacyHits, body)
			call := len(plane.legacyHits)
			plane.mu.Unlock()
			plane.legacy(w, r, call)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	t.Setenv("TR_CONTROL_PLANE_BASE_URL", server.URL)
	t.Setenv("TR_INTERNAL_GATEWAY_TOKEN", "test")
	gateway := trustedrouter.New(server.URL, "test", server.Client())
	req := &types.OpenAIChatRequest{Model: "openai/billing-v1", Stream: true, IdempotencyKey: "sync-deadline", StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}
	auth, err := gateway.AuthorizeWithRoute(t.Context(), "key", req, "chat.completions")
	if err != nil {
		t.Fatal(err)
	}
	if !gateway.AsyncSettlementNegotiated(auth) {
		t.Fatal("async settlement was not negotiated")
	}
	provider := &asyncCleanupProvider{release: make(chan struct{}), stopped: make(chan struct{})}
	close(provider.release)
	var out asyncOutput
	logs := captureStderr(t, func() {
		serveStreaming(t.Context(), &out, provider, req, &types.AnthropicMessagesRequest{},
			[]llm.InvokeOptions{{Model: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID}},
			gateway, auth, nil, time.Now(), nil, "chat.completions", "async-sync-deadline", auth.Model)
	})
	if !strings.Contains(out.String(), "data: [DONE]") {
		t.Fatalf("stream did not finish: %s", out.String())
	}
	return logs
}

// contextUntil is ctx, also ended when release closes (test cleanup), so a
// handler that holds a request open until its client leaves cannot outlive the
// test's server.
func contextUntil(ctx context.Context, release <-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-release:
		case <-ctx.Done():
		}
		cancel()
	}()
	return ctx
}

func installRetryQueue(t *testing.T, q *settlementRetryQueue) {
	t.Helper()
	q.Start(t.Context())
	original := settlementRetries
	settlementRetries = q
	t.Cleanup(func() {
		q.ReleaseDeferred()
		settlementRetries = original
	})
}

func writeSettled(w http.ResponseWriter, cost int64) {
	_, _ = fmt.Fprintf(w, `{"data":{"settled":true,"cost_microdollars":%d,"generation_id":"gen-v1"}}`, cost)
}

func hangUp(t *testing.T, w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	_ = conn.Close()
}

var retryDeferredDelay = regexp.MustCompile(`enclave\.settlement_retry_deferred [^\n]* delay_ms=(\d+)`)

// The terminal paths bound the whole settle by QUILL_SETTLE_BEFORE_TERMINAL_MS.
// When a sync_required settle's snapshot sync runs past that bound, the router
// keeps applying it after the gateway stops waiting. The queued retry is a
// legacy settle for the same reservation, so it must be held for
// abandonedSettleRetryDelay instead of racing the abandoned apply. Before the
// fix the deadline reached the queue as "network" and the retry went at once.
func TestAsyncSnapshotSyncAbandonedAtTerminalDeadlineHoldsFirstRetry(t *testing.T) {
	t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "300")
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1, abandonedDelay: abandonedSettleRetryDelay}
	installRetryQueue(t, q)
	plane := &asyncSyncPlane{
		// The router is still applying the snapshot sync when the gateway's
		// terminal wait ends; the request ends only when the gateway leaves.
		sync: func(_ http.ResponseWriter, r *http.Request, _ int) { <-r.Context().Done() },
		legacy: func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeSettled(w, 2)
		},
	}
	logs := serveAsyncSyncStream(t, plane)

	if syncCalls, legacyCalls := plane.counts(); syncCalls != 1 || legacyCalls != 0 {
		t.Fatalf("sync=%d legacy=%d at stream end, want the one abandoned snapshot sync and no legacy settle", syncCalls, legacyCalls)
	}
	if q.deferred.Load() != 1 || len(q.jobs) != 0 {
		t.Fatalf("deferred=%d queued=%d, want the first retry held off the queue; logs=%s", q.deferred.Load(), len(q.jobs), logs)
	}
	if !strings.Contains(logs, "enclave.stream_settle_failed") || !strings.Contains(logs, "context deadline exceeded") {
		t.Fatalf("settle failure does not name the deadline; logs=%s", logs)
	}
	match := retryDeferredDelay.FindStringSubmatch(logs)
	if match == nil {
		t.Fatalf("no settlement_retry_deferred line; logs=%s", logs)
	}
	held, _ := strconv.Atoi(match[1])
	if want := abandonedSettleRetryDelay.Milliseconds(); int64(held) > want || int64(held) < want-1000 {
		t.Fatalf("retry held %d ms, want the %d ms abandoned-settle hold", held, want)
	}
	time.Sleep(100 * time.Millisecond)
	if _, legacyCalls := plane.counts(); legacyCalls != 0 {
		t.Fatalf("legacy=%d during the hold, want none", legacyCalls)
	}

	// Release the hold the way shutdown does. The retry then takes the queue's
	// ordinary first-attempt timing (no delay), on the legacy route, once.
	flush, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	q.Flush(flush)
	if flush.Err() != nil {
		t.Fatal("flush did not finish before its deadline")
	}
	syncCalls, legacyCalls := plane.counts()
	if syncCalls != 1 || legacyCalls != 1 || q.deferred.Load() != 0 {
		t.Fatalf("sync=%d legacy=%d deferred=%d after release, want one legacy retry", syncCalls, legacyCalls, q.deferred.Load())
	}
	plane.mu.Lock()
	retry := string(plane.legacyHits[0])
	plane.mu.Unlock()
	if !strings.Contains(retry, `"authorization_id":"auth-v1"`) || strings.Contains(retry, "settlement_ticket") {
		t.Fatalf("retry body is not the legacy settle: %s", retry)
	}
}

// Everything else about the async settle and its retry keeps its timing: a
// snapshot sync that answers is not retried, a hard snapshot-sync failure falls
// back to the legacy settle in-line, and a genuine network failure of that
// legacy settle is retried at once, without the hold.
func TestAsyncSnapshotSyncOutcomesKeepRetryTiming(t *testing.T) {
	for _, scenario := range []string{"snapshot_sync_settled", "snapshot_sync_server_error", "network_then_legacy_reset"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("QUILL_SETTLE_BEFORE_TERMINAL_MS", "5000")
			q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1, abandonedDelay: abandonedSettleRetryDelay}
			installRetryQueue(t, q)
			retried := make(chan time.Time, 1)
			plane := &asyncSyncPlane{}
			switch scenario {
			case "snapshot_sync_settled":
				plane.sync = func(w http.ResponseWriter, r *http.Request, _ int) {
					var body struct {
						Terminal billingv1.TerminalEnvelope `json:"terminal"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					writeSettled(w, body.Terminal.ChargeMicro)
				}
				plane.legacy = func(w http.ResponseWriter, _ *http.Request, _ int) {
					t.Error("legacy settle after a settled snapshot sync")
				}
			case "snapshot_sync_server_error":
				plane.sync = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusServiceUnavailable) }
				plane.legacy = func(w http.ResponseWriter, _ *http.Request, _ int) { writeSettled(w, 2) }
			case "network_then_legacy_reset":
				plane.sync = func(w http.ResponseWriter, _ *http.Request, _ int) { hangUp(t, w) }
				plane.legacy = func(w http.ResponseWriter, _ *http.Request, call int) {
					// The in-line legacy settle makes three attempts; the queued
					// retry is the fourth.
					if call <= 3 {
						hangUp(t, w)
						return
					}
					retried <- time.Now()
					writeSettled(w, 2)
				}
			}
			logs := serveAsyncSyncStream(t, plane)
			streamEnded := time.Now()
			syncCalls, legacyCalls := plane.counts()
			switch scenario {
			case "snapshot_sync_settled":
				if syncCalls != 1 || legacyCalls != 0 || strings.Contains(logs, "settlement_retry") {
					t.Fatalf("sync=%d legacy=%d, want one snapshot sync and no retry; logs=%s", syncCalls, legacyCalls, logs)
				}
			case "snapshot_sync_server_error":
				if syncCalls != 3 || legacyCalls != 1 || !strings.Contains(logs, `event="legacy_fallback" reason="snapshot_sync_server_error"`) || strings.Contains(logs, "settlement_retry") {
					t.Fatalf("sync=%d legacy=%d, want three snapshot syncs, one in-line legacy settle and no retry; logs=%s", syncCalls, legacyCalls, logs)
				}
			case "network_then_legacy_reset":
				if syncCalls != 3 || !strings.Contains(logs, `event="legacy_fallback" reason="snapshot_sync_network"`) || strings.Contains(logs, "settlement_retry_deferred") {
					t.Fatalf("sync=%d legacy=%d, want three snapshot syncs, the legacy fallback and an unheld retry; logs=%s", syncCalls, legacyCalls, logs)
				}
				select {
				case arrived := <-retried:
					if waited := arrived.Sub(streamEnded); waited > time.Second {
						t.Fatalf("network-error retry waited %s after the stream", waited)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("network-error retry was never sent")
				}
			}
			if q.deferred.Load() != 0 {
				t.Fatalf("deferred=%d, want no held retry", q.deferred.Load())
			}
		})
	}
}
