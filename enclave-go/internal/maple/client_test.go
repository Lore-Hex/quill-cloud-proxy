package maple

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

func testBody() []byte {
	return []byte(`{"model":"` + Model + `","stream":true,"messages":[{"role":"user","content":"synthetic"}]}`)
}

func rootOf(t *testing.T, scope string) string {
	t.Helper()
	data, err := encodeInput("synthetic-key", scope, testBody())
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Root string `json:"cache_root"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	root, err := base64.StdEncoding.DecodeString(wire.Root)
	if err != nil || len(root) != 32 {
		t.Fatal("invalid root")
	}
	return wire.Root
}

func TestWorkspaceCacheIsolation(t *testing.T) {
	a := rootOf(t, "authorized-a")
	if a != rootOf(t, "authorized-a") || a == rootOf(t, "authorized-b") {
		t.Fatal("workspace roots are not stable and isolated")
	}
	if rootOf(t, "") == rootOf(t, "") {
		t.Fatal("anonymous requests share a root")
	}
}

func TestRejectsRequestsBeforeLaunch(t *testing.T) {
	for _, tc := range []struct {
		key  string
		body []byte
	}{
		{"", testBody()},
		{strings.Repeat("x", 8193), testBody()},
		{"key", []byte(`null`)},
		{"key", []byte(`{`)},
		{"key", []byte(`{"model":"deepseek-v4-1-flash","stream":true}`)},
		{"key", []byte(`{"model":"` + Model + `","stream":false}`)},
		{"key", bytes.Repeat([]byte("x"), requestLimit+1)},
	} {
		_, _, err := start(t.Context(), tc.key, "scope", tc.body,
			func(context.Context, []byte, uint32) (process, error) {
				t.Fatal("invalid request launched a process")
				return process{}, nil
			})
		if err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestRelayRequiresSuccessfulExitBeforeDone(t *testing.T) {
	for _, tc := range []struct {
		name, stream string
		exitErr      error
		valid        bool
	}{
		{"success", "data: {}\n\ndata: [DONE]\n\n", nil, true},
		{"truncated", "data: {}\n\n", nil, false},
		{"partial-line", "data: {}", nil, false},
		{"failed-exit", "data: {}\n\ndata: [DONE]\n\n", errors.New("synthetic"), false},
		{"tail", "data: [DONE]\n\ndata: {}\n", nil, false},
		{"large-tail", "data: [DONE]\n" + strings.Repeat(" ", 65), nil, false},
		{"large-line", strings.Repeat("x", lineLimit+1) + "\n", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			waited := false
			err := relay(bufio.NewReaderSize(strings.NewReader(tc.stream), lineLimit), &out, func() error {
				if strings.Contains(out.String(), "[DONE]") {
					t.Fatal("DONE preceded process exit")
				}
				waited = true
				return tc.exitErr
			})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if strings.Contains(out.String(), "[DONE]") != tc.valid {
				t.Fatal("invalid terminal forwarding")
			}
			if tc.valid && !waited {
				t.Fatal("process was not reaped")
			}
		})
	}
}

func TestAdapterStatusAndResourceRelease(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		status       int
		exitErr      error
	}{
		{"stream", "{\"status\":200}\ndata: {}\n\ndata: [DONE]\n\n", 200, nil},
		{"auth", "{\"status\":401}\n", 401, nil},
		{"auth-failed-exit", "{\"status\":401}\n", 0, errors.New("secret untrusted body")},
		{"redirect", "{\"status\":302}\n", 0, nil},
		{"missing-status", "{}\n", 0, nil},
		{"malformed", "not-json\n", 0, nil},
		{"truncated", "{\"status\":200}", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var waits atomic.Int32
			status, body, err := start(t.Context(), "synthetic-key", "scope", testBody(), func(ctx context.Context, input []byte, uid uint32) (process, error) {
				if uid < childUID || uid >= childUID+concurrency {
					t.Fatal("invalid isolation UID")
				}
				if !bytes.Contains(input, []byte("synthetic-key")) {
					t.Fatal("missing input")
				}
				return process{stdout: io.NopCloser(strings.NewReader(tc.output)), wait: func() error { waits.Add(1); return tc.exitErr }}, nil
			})
			if status != tc.status || (err == nil) != (tc.status != 0) {
				t.Fatalf("status=%d err=%v", status, err)
			}
			if body != nil {
				if _, err := io.Copy(io.Discard, body); err != nil {
					t.Fatal(err)
				}
				if err := body.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if waits.Load() != 1 || len(slots) != concurrency {
				t.Fatal("process or concurrency slot leaked")
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("untrusted process error exposed")
			}
		})
	}
}

func TestConsumerCancellationReapsAdapter(t *testing.T) {
	var waits atomic.Int32
	status, body, err := start(t.Context(), "synthetic-key", "scope", testBody(), func(ctx context.Context, _ []byte, _ uint32) (process, error) {
		r, w := io.Pipe()
		go func() {
			_, _ = io.WriteString(w, "{\"status\":200}\n")
			<-ctx.Done()
			_ = w.CloseWithError(ctx.Err())
		}()
		return process{stdout: r, wait: func() error { waits.Add(1); return ctx.Err() }}, nil
	})
	if err != nil || status != 200 {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if waits.Load() != 1 || len(slots) != concurrency {
		t.Fatal("cancelled process or slot leaked")
	}
}

func TestCapacityIsBounded(t *testing.T) {
	var acquired []uint32
	for range concurrency {
		acquired = append(acquired, <-slots)
	}
	defer func() {
		for _, uid := range acquired {
			slots <- uid
		}
	}()
	_, _, err := start(t.Context(), "synthetic-key", "scope", testBody(), func(context.Context, []byte, uint32) (process, error) {
		t.Fatal("capacity exceeded")
		return process{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatal(err)
	}
}
