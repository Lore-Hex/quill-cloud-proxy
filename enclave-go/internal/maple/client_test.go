package maple

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	firstAnonymousRoot := rootOf(t, "")
	secondAnonymousRoot := rootOf(t, "")
	if firstAnonymousRoot == secondAnonymousRoot {
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

// helperPreStatusReasons reads maple-transport's PRE_STATUS_REASONS from the
// helper's source, so the two lists cannot drift apart.
func helperPreStatusReasons(t *testing.T) []string {
	t.Helper()
	source, err := os.ReadFile("../../maple-transport/src/bin/maple-transport.rs")
	if err != nil {
		t.Fatalf("read the helper source: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "const PRE_STATUS_REASONS: &[&str] = &[")
	if start < 0 {
		t.Fatal("helper source has no PRE_STATUS_REASONS")
	}
	end := strings.Index(text[start:], "];")
	if end < 0 {
		t.Fatal("PRE_STATUS_REASONS is not terminated")
	}
	var reasons []string
	for _, match := range regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(text[start:start+end], -1) {
		reasons = append(reasons, match[1])
	}
	if len(reasons) < 10 {
		t.Fatalf("parsed only %d helper reasons", len(reasons))
	}
	return reasons
}

func TestEveryHelperReasonHasAFixedStartFailure(t *testing.T) {
	reasons := helperPreStatusReasons(t)
	for _, reason := range reasons {
		failure := adapterFailures[reason]
		if failure == nil || errors.Is(failure, ErrInvalidAdapterStatus) || StartFailure(failure) != failure {
			t.Errorf("reason %q maps to %v", reason, failure)
		}
	}
	if len(adapterFailures) != len(reasons) {
		t.Errorf("adapterFailures has %d reasons, the helper %d", len(adapterFailures), len(reasons))
	}
	for _, known := range startFailures {
		if StartFailure(known.err) != known.err || StartFailureClass(known.err) != known.class ||
			!strings.HasPrefix(known.class, "maple_") {
			t.Errorf("start failure %v is not labelled", known.err)
		}
		wrapped := fmt.Errorf("context %w", known.err)
		if StartFailure(wrapped) != known.err {
			t.Errorf("StartFailure must return the package's own value for %v", wrapped)
		}
	}
	for _, other := range []error{errors.New("maple: front enclave attestation rejected"), context.Canceled, io.EOF} {
		if StartFailure(other) != nil || StartFailureClass(other) != "" {
			t.Errorf("StartFailure(%v) matched; only this package's own values qualify", other)
		}
	}
}

func TestAStartTimeoutIsLabelledAsOne(t *testing.T) {
	previous := startBudget
	startBudget = 50 * time.Millisecond
	t.Cleanup(func() { startBudget = previous })
	status, body, err := start(t.Context(), "synthetic-key", "scope", testBody(), func(ctx context.Context, _ []byte, _ uint32) (process, error) {
		reader, writer := io.Pipe()
		go func() {
			<-ctx.Done()
			_ = writer.Close()
		}()
		return process{stdout: reader, wait: func() error { return errors.New("signal: killed") }}, nil
	})
	if status != 0 || body != nil || !errors.Is(err, ErrResponseStartTimeout) {
		t.Fatalf("status=%d body=%v err=%v", status, body != nil, err)
	}
	if len(slots) != concurrency {
		t.Fatal("concurrency slot leaked")
	}
}

func TestAdapterFailureLineBecomesAFixedError(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         error
	}{
		{"attestation", "{\"error\":\"attestation_rejected\"}\n", ErrAttestationRejected},
		{"send", "{\"error\":\"encrypted_request_failed\"}\n", ErrRequestFailed},
		{"start timeout", "{\"error\":\"response_start_timeout\"}\n", ErrResponseStartTimeout},
		{"setup", "{\"error\":\"client_initialization_failed\"}\n", ErrAdapterSetupFailed},
		{"input", "{\"error\":\"invalid_credential\"}\n", ErrAdapterInputRejected},
		{"unknown reason", "{\"error\":\"secret helper text\"}\n", ErrInvalidAdapterStatus},
		{"empty reason", "{\"error\":\"\"}\n", ErrInvalidAdapterStatus},
		{"reason beside a bad status", "{\"status\":302,\"error\":\"attestation_rejected\"}\n", ErrInvalidAdapterStatus},
		{"oversized", "{\"error\":\"attestation_rejected\",\"pad\":\"" + strings.Repeat("x", 64) + "\"}\n", ErrInvalidAdapterStatus},
		{"no newline", "{\"error\":\"attestation_rejected\"}", ErrInvalidAdapterStatus},
		{"not a string", "{\"error\":7}\n", ErrInvalidAdapterStatus},
		{"known reason beside a malformed status", "{\"error\":\"attestation_rejected\",\"status\":\"x\"}\n", ErrInvalidAdapterStatus},
		{"upstream error body", "{\"error\":\"error_body_too_large\"}\n", ErrUpstreamErrorUnreadable},
		{"nothing", "", ErrInvalidAdapterStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var waits atomic.Int32
			status, body, err := start(t.Context(), "synthetic-key", "scope", testBody(), func(context.Context, []byte, uint32) (process, error) {
				return process{stdout: io.NopCloser(strings.NewReader(tc.output)), wait: func() error {
					waits.Add(1)
					return errors.New("exit status 1")
				}}, nil
			})
			if status != 0 || body != nil || !errors.Is(err, tc.want) {
				t.Fatalf("status=%d body=%v err=%v, want %v", status, body != nil, err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "exit status") {
				t.Fatalf("helper text leaked: %v", err)
			}
			if waits.Load() != 1 || len(slots) != concurrency {
				t.Fatal("process or concurrency slot leaked")
			}
		})
	}
}

// TestErrorStatusCarriesOnlyKnownCodes: an error status line's code reaches
// the caller as the body only when it is one of Maple's known error codes, and
// the known codes are exactly maple-transport's ERROR_CODES.
func TestErrorStatusCarriesOnlyKnownCodes(t *testing.T) {
	source, err := os.ReadFile("../../maple-transport/src/bin/maple-transport.rs")
	if err != nil {
		t.Fatalf("read the helper source: %v", err)
	}
	text := string(source)
	begin := strings.Index(text, "const ERROR_CODES: &[&str] = &[")
	if begin < 0 {
		t.Fatal("helper source has no ERROR_CODES")
	}
	end := strings.Index(text[begin:], "];")
	var helperCodes []string
	for _, match := range regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(text[begin:begin+end], -1) {
		helperCodes = append(helperCodes, match[1])
	}
	if len(helperCodes) != len(errorCodes) || len(helperCodes) < 4 {
		t.Fatalf("helper has %d codes, errorCodes %d", len(helperCodes), len(errorCodes))
	}
	for _, code := range helperCodes {
		if ErrorCode(code) != code {
			t.Errorf("helper code %q is not accepted", code)
		}
	}
	for _, tc := range []struct{ line, body string }{
		{"{\"status\":403,\"code\":\"usage_limit_reached\"}\n", "usage_limit_reached"},
		{"{\"status\":403,\"code\":\"model_not_available_on_plan\"}\n", "model_not_available_on_plan"},
		{"{\"status\":403,\"code\":\"secret prompt text\"}\n", ""},
		{"{\"status\":403}\n", ""},
	} {
		status, body, err := start(t.Context(), "synthetic-key", "scope", testBody(), func(context.Context, []byte, uint32) (process, error) {
			return process{stdout: io.NopCloser(strings.NewReader(tc.line)), wait: func() error { return nil }}, nil
		})
		if err != nil || status != 403 {
			t.Fatalf("%q: status=%d err=%v", tc.line, status, err)
		}
		got, _ := io.ReadAll(body)
		_ = body.Close()
		if string(got) != tc.body {
			t.Errorf("%q: body %q, want %q", tc.line, got, tc.body)
		}
	}
}
