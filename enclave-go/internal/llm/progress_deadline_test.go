package llm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLongStreamingClientIsProviderScoped(t *testing.T) {
	ordinary := newOpenAICompatible("deepinfra", "test")
	long := newOpenAICompatible("hixtube", "test")
	if ordinary.httpc.Timeout != defaultStreamingHTTPTimeout || long.httpc.Timeout != time.Hour {
		t.Fatal("incorrect scoped total deadline")
	}
	transport, ok := long.httpc.Transport.(*progressDeadlineTransport)
	if !ok || transport.base == nil || transport.timeout != 30*time.Second {
		t.Fatal("long requests must retain a cloud transport and progress deadline")
	}
	if _, ok := ordinary.httpc.Transport.(*progressDeadlineTransport); ok {
		t.Fatal("unrelated provider transport changed")
	}
}

func TestProgressDeadlineStopsStalls(t *testing.T) {
	for _, stage := range []string{"headers", "first-byte", "later-byte"} {
		t.Run(stage, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage != "headers" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				if stage == "later-byte" {
					_, _ = w.Write([]byte("x"))
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			client.Transport = &progressDeadlineTransport{base: client.Transport, timeout: 100 * time.Millisecond}
			start := time.Now()
			response, err := client.Get(server.URL)
			if err == nil {
				_, err = io.ReadAll(response.Body)
				_ = response.Body.Close()
			}
			if err == nil || time.Since(start) >= 2*time.Second {
				t.Fatalf("stall did not fail promptly: %v", err)
			}
		})
	}
}

func TestProgressDeadlineAllowsProgressAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 10 {
			_, _ = w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(30 * time.Millisecond):
			}
		}
	}))
	defer server.Close()
	for _, cancelEarly := range []bool{false, true} {
		client := server.Client()
		client.Timeout = 3 * time.Second
		client.Transport = &progressDeadlineTransport{base: client.Transport, timeout: 200 * time.Millisecond}
		ctx, cancel := context.WithCancel(t.Context())
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		response, err := client.Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if cancelEarly {
			cancel()
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		cancel()
		if cancelEarly && err == nil {
			t.Fatal("caller cancellation was ignored")
		}
		if !cancelEarly && (err != nil || string(body) != "xxxxxxxxxx") {
			t.Fatalf("active stream cut short: %d bytes, %v", len(body), err)
		}
	}
}
