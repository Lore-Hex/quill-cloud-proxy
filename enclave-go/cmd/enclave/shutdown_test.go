package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestServeUntilCanceledWaitsForActiveHandler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	releaseHandler := func() { once.Do(func() { close(release) }) }
	defer releaseHandler()
	done := make(chan error, 1)
	go func() {
		done <- serveUntilCanceled(ctx, listener, func(requestContext context.Context, conn net.Conn) {
			defer conn.Close()
			close(started)
			<-release
			if requestContext.Err() != nil {
				t.Error("shutdown canceled an active request before its grace period")
			}
		})
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("shutdown returned before the active request completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	releaseHandler()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after the request completed")
	}
}

func TestDrainForceCancelsStuckRequestButWaitsForCleanup(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	canceled := make(chan struct{})
	cleanup := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(cleanup) }) }
	defer release()
	done := make(chan error, 1)
	go func() {
		done <- serveWithDrain(ctx, listener, func(requestContext context.Context, conn net.Conn) {
			close(started)
			<-requestContext.Done()
			close(canceled)
			<-cleanup
		}, 30*time.Millisecond, time.Second)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-started
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("stuck provider was not canceled at the drain deadline")
	}
	select {
	case <-done:
		t.Fatal("server did not wait for cancellation cleanup")
	default:
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not finish after cleanup")
	}
}

func TestDrainClosesIdleConnectionsWithoutWaitingForGrace(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idle := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveWithDrain(ctx, listener, func(requestContext context.Context, conn net.Conn) {
			markConnectionIdle(requestContext)
			close(idle)
			_, _ = conn.Read(make([]byte, 1))
		}, time.Minute, time.Second)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-idle
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle connection consumed the request drain grace period")
	}
}

func TestDrainIsBoundedWhenHandlerIgnoresCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	done := make(chan error, 1)
	go func() {
		done <- serveWithDrain(ctx, listener, func(_ context.Context, _ net.Conn) {
			close(started)
			<-release
		}, 20*time.Millisecond, 20*time.Millisecond)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("uncooperative handler blocked shutdown indefinitely")
	}
}

func TestDrainRejectsNewRequestBeforeListenerWatcherRuns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	drain := &connectionDrain{shutdown: ctx, active: make(map[*drainConnection]bool)}
	c := &drainConnection{owner: drain, conn: server}
	requestContext := context.WithValue(context.Background(), drainConnectionKey{}, c)
	if !beginConnectionRequest(requestContext) {
		t.Fatal("live server rejected a request")
	}
	cancel()
	if beginConnectionRequest(requestContext) {
		t.Fatal("canceled server admitted another request")
	}
	if markConnectionIdle(requestContext) {
		t.Fatal("canceled server allowed keepalive reuse")
	}
}

func TestShutdownHealthFailsClosedDuringDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := shutdownHealthHandler(ctx)
	before := httptest.NewRecorder()
	handler.ServeHTTP(before, httptest.NewRequest("GET", "/health", nil))
	if before.Code != http.StatusOK {
		t.Fatalf("live health = %d", before.Code)
	}
	cancel()
	after := httptest.NewRecorder()
	handler.ServeHTTP(after, httptest.NewRequest("GET", "/health", nil))
	if after.Code != http.StatusServiceUnavailable || after.Body.String() != "draining\n" {
		t.Fatalf("draining health = %d %q", after.Code, after.Body.String())
	}
}

func TestDrainAllowsRealSettlementAndHTTPResponseToFinish(t *testing.T) {
	var settlementCalls atomic.Int32
	billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/settle" {
			t.Errorf("unexpected billing path %q", r.URL.Path)
		}
		settlementCalls.Add(1)
		_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_drain","cost_microdollars":42}}`)
	}))
	defer billing.Close()
	gateway := trustedrouter.New(billing.URL, "internal-test", billing.Client())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	done := make(chan error, 1)
	go func() {
		done <- serveWithDrain(ctx, listener, func(requestContext context.Context, conn net.Conn) {
			if !beginConnectionRequest(requestContext) {
				return
			}
			close(started)
			<-release
			if requestContext.Err() != nil {
				return
			}
			_, settleErr := gateway.Settle(requestContext,
				&trustedrouter.Authorization{AuthorizationID: "auth_drain", Model: "test/model"},
				trustedrouter.Usage{RequestID: "req_drain", InputTokens: 1, OutputTokens: 1})
			if settleErr != nil {
				t.Errorf("settlement was interrupted by shutdown: %v", settleErr)
				return
			}
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			markConnectionIdle(requestContext)
		}, time.Second, time.Second)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	<-started
	cancel()
	finish()
	body, err := io.ReadAll(client)
	if err != nil || !strings.HasSuffix(string(body), "\r\n\r\nok") {
		t.Fatalf("response interrupted during drain: %q %v", body, err)
	}
	if settlementCalls.Load() != 1 {
		t.Fatalf("settlement calls = %d, want exactly one", settlementCalls.Load())
	}
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestServeOneDrainsChatAndDoesNotAuthorizePipelinedRequests(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", streamed), func(t *testing.T) {
			t.Setenv("QUILL_KEEPALIVE", "on")
			var authorizations, settlements atomic.Int32
			settleStarted := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authorizations.Add(1)
					_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_drain","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","route_candidates":[]}}`)
				case "/internal/gateway/settle":
					if settlements.Add(1) == 1 {
						close(settleStarted)
					}
					select {
					case <-release:
					case <-r.Context().Done():
						t.Error("in-flight settlement canceled by shutdown")
						return
					}
					_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_drain","cost_microdollars":12}}`)
				default:
					t.Errorf("unexpected billing call %s", r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer billing.Close()
			defer finish()
			gateway := trustedrouter.New(billing.URL, "internal-test", billing.Client())
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- serveWithDrain(ctx, listener, func(requestContext context.Context, conn net.Conn) {
					serveOne(requestContext, conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
				}, time.Second, time.Second)
			}()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			body := fmt.Sprintf(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"test"}],"stream":%t}`, streamed)
			request := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-user-bearer\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			if _, err := io.WriteString(client, request+request); err != nil {
				t.Fatal(err)
			}
			select {
			case <-settleStarted:
			case <-time.After(time.Second):
				t.Fatal("request did not reach settlement")
			}
			cancel()
			finish()
			reader := bufio.NewReader(client)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			output, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				t.Fatalf("drained response: status=%d body=%s err=%v", response.StatusCode, output, err)
			}
			if streamed && !strings.Contains(string(output), "[DONE]") {
				t.Fatalf("stream was truncated: %s", output)
			}
			if !streamed && !strings.Contains(string(output), "Hello world") {
				t.Fatalf("response lost output: %s", output)
			}
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
				t.Fatalf("connection stayed reusable during drain: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if authorizations.Load() != 1 || settlements.Load() != 1 {
				t.Fatalf("authorization/settlement calls = %d/%d, want 1/1", authorizations.Load(), settlements.Load())
			}
		})
	}
}

func TestSettlementDrainWaitsForInFlightRetry(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, `{"data":{"generation_id":"gen_drain"}}`)
	}))
	defer server.Close()
	defer finish()
	workerContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1), maxAttempts: 1}
	q.Start(workerContext)
	q.Enqueue(settlementRetryJob{
		trGateway:     trustedrouter.New(server.URL, "internal-test", server.Client()),
		authorization: &trustedrouter.Authorization{AuthorizationID: "auth_drain"},
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("retry did not start")
	}
	if len(q.jobs) != 0 {
		t.Fatal("test requires a dequeued but in-flight job")
	}
	short, stopShort := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stopShort()
	if err := q.WaitForIdle(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("in-flight retry reported idle: %v", err)
	}
	finish()
	flush, stopFlush := context.WithTimeout(context.Background(), time.Second)
	defer stopFlush()
	if err := q.WaitForIdle(flush); err != nil {
		t.Fatalf("finished retry did not report idle: %v", err)
	}
}

func TestSettlementDrainDisabledQueueDoesNotWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (*settlementRetryQueue)(nil).WaitForIdle(ctx); err != nil {
		t.Fatal(err)
	}
}
