package streamhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type tickingBody struct {
	ctx       context.Context
	ticker    *time.Ticker
	remaining int
}

func (b *tickingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-b.ticker.C:
		if b.remaining > 0 {
			b.remaining--
		}
		p[0] = 'x'
		return 1, nil
	}
}
func (b *tickingBody) Close() error { b.ticker.Stop(); return nil }

func TestFusionProgressTimeout(t *testing.T) {
	// Scale the old ten-minute total to 40ms. Progress lasts six times longer.
	const oldTotal = 40 * time.Millisecond
	for _, tt := range []struct {
		name                string
		fusion              bool
		headersStall        bool
		period, idle, total time.Duration
		count               int
		wantError           bool
	}{
		{"progress survives old total", true, false, 20 * time.Millisecond, 150 * time.Millisecond, 2 * time.Second, 12, false},
		{"direct retains old total", false, false, 20 * time.Millisecond, 150 * time.Millisecond, 2 * time.Second, 12, true},
		{"body stalls", true, false, time.Hour, 60 * time.Millisecond, time.Second, -1, true},
		{"headers stall", true, true, time.Hour, 60 * time.Millisecond, time.Second, -1, true},
		{"total bounds continuous progress", true, false, 10 * time.Millisecond, 150 * time.Millisecond, 100 * time.Millisecond, -1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.fusion {
				ctx = context.WithValue(ctx, fusionTimeoutKey{}, timeouts{tt.idle, tt.total})
			}
			client := &http.Client{Timeout: oldTotal, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if tt.headersStall {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &tickingBody{r.Context(), time.NewTicker(tt.period), tt.count}}, nil
			})}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://provider.test/chat", nil)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			resp, err := Do(client, req)
			var got []byte
			if err == nil {
				defer resp.Body.Close()
				got, err = io.ReadAll(resp.Body)
			}
			if tt.wantError {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error = %v, want deadline exceeded", err)
				}
			} else {
				if err != nil || len(got) != tt.count {
					t.Fatalf("got %q, error %v", got, err)
				}
				if time.Since(start) <= oldTotal {
					t.Fatal("did not exceed old total")
				}
			}
			if tt.fusion && strings.Contains(tt.name, "stall") && !strings.Contains(err.Error(), "idle timeout") {
				t.Fatalf("wrong deadline: %v", err)
			}
			if client.Timeout != oldTotal {
				t.Fatal("mutated shared client")
			}
		})
	}
}

func TestFusionTimeoutCancellationAndClose(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "parent cancellation"}[cancelParent], func(t *testing.T) {
			ctx, cancel := context.WithCancel(WithFusionTimeout(context.Background()))
			defer cancel()
			var upstream context.Context
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				upstream = r.Context()
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &tickingBody{r.Context(), time.NewTicker(time.Hour), -1}}, nil
			})}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://provider.test/chat", nil)
			resp, err := Do(client, req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if cancelParent {
				cancel()
				if _, err := io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v", err)
				}
			} else {
				_ = resp.Body.Close()
			}
			select {
			case <-upstream.Done():
			case <-time.After(time.Second):
				t.Fatal("upstream context not released")
			}
			body := resp.Body.(*progressBody)
			body.watch.mu.Lock()
			stopped := body.watch.stopped
			body.watch.mu.Unlock()
			if !stopped {
				t.Fatal("idle timer not stopped")
			}
		})
	}
}

// A zero-timeout client models NEAR's pinned connection. No sockets are used.
func TestDirectStreamIdleDeadline(t *testing.T) {
	t.Setenv("QUILL_STREAM_IDLE_TIMEOUT_MS", "100")
	for _, progress := range []bool{false, true} {
		t.Run(map[bool]string{false: "silent_200", true: "stalls_after_progress"}[progress], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				pr, pw := io.Pipe()
				go func() {
					stop := context.AfterFunc(r.Context(), func() { _ = pw.CloseWithError(r.Context().Err()) })
					defer stop()
					defer pw.Close()
					if progress {
						for i := 0; i < 12; i++ {
							if _, err := pw.Write([]byte(": thinking\n\n")); err != nil {
								return
							}
							time.Sleep(20 * time.Millisecond)
						}
					}
					<-r.Context().Done()
				}()
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: pr}, nil
			})}
			req, _ := http.NewRequestWithContext(ctx, "POST", "https://provider.invalid/chat", nil)
			resp, err := Do(client, req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "idle timeout") {
				t.Fatalf("silent accepted stream not bounded by idle deadline: %v", err)
			}
			if progress && len(got) != 12*len(": thinking\n\n") {
				t.Fatalf("raw keepalives failed to reset idle deadline: %q", got)
			}
		})
	}
}
