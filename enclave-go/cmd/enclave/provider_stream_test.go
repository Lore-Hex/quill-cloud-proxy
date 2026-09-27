package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const providerStreamTestResponse = `event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":1,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}

event: message_stop
data: {"type":"message_stop"}

`

type scriptedProviderStreamClient struct {
	mu       sync.Mutex
	attempts []llm.InvokeOptions
	invoke   func(llm.InvokeOptions, io.Writer) error
}

type blockingFirstByteClient struct {
	started chan struct{}
	release chan struct{}
}

type stageCCancelClient struct {
	started             chan struct{}
	done                chan struct{}
	speculativeResponse string
	redispatchResponse  string

	mu                    sync.Mutex
	attempts              []llm.InvokeOptions
	speculativeWriteBytes int
}

func (c *stageCCancelClient) InvokeStreaming(
	ctx context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	options ...llm.InvokeOptions,
) error {
	option := llm.InvokeOptions{}
	if len(options) > 0 {
		option = options[0]
	}
	c.mu.Lock()
	c.attempts = append(c.attempts, option)
	attempt := len(c.attempts)
	c.mu.Unlock()

	if attempt == 1 {
		close(c.started)
		if c.speculativeResponse != "" {
			written, _ := io.WriteString(out, c.speculativeResponse)
			c.mu.Lock()
			c.speculativeWriteBytes = written
			c.mu.Unlock()
		}
		<-ctx.Done()
		close(c.done)
		return ctx.Err()
	}
	_, err := io.WriteString(out, c.redispatchResponse)
	return err
}

func (c *stageCCancelClient) snapshot() ([]string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	endpoints := make([]string, 0, len(c.attempts))
	for _, attempt := range c.attempts {
		endpoints = append(endpoints, attempt.EndpointID)
	}
	return endpoints, c.speculativeWriteBytes
}

func (c *blockingFirstByteClient) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	close(c.started)
	<-c.release
	_, err := io.WriteString(out, providerStreamTestResponse)
	return err
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *synchronizedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Len()
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (c *scriptedProviderStreamClient) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	options ...llm.InvokeOptions,
) error {
	option := llm.InvokeOptions{}
	if len(options) > 0 {
		option = options[0]
	}
	c.mu.Lock()
	c.attempts = append(c.attempts, option)
	c.mu.Unlock()
	return c.invoke(option, out)
}

func (c *scriptedProviderStreamClient) endpoints() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	endpoints := make([]string, 0, len(c.attempts))
	for _, attempt := range c.attempts {
		endpoints = append(endpoints, attempt.EndpointID)
	}
	return endpoints
}

func runProviderStreamTest(
	t *testing.T,
	client llm.Client,
	options []llm.InvokeOptions,
) ([]byte, error, *selectedRouteTracker) {
	t.Helper()
	pr, pw := io.Pipe()
	selected := newSelectedRouteTracker()
	done := make(chan struct{})
	go func() {
		defer close(done)
		invokeProviderStream(
			context.Background(), client,
			&types.OpenAIChatRequest{Model: "requested-model"},
			&types.AnthropicMessagesRequest{}, pw, options,
			true, nil, selected, "zero-byte-test", false, false,
		)
	}()
	body, err := io.ReadAll(pr)
	<-done
	return body, err, selected
}

func TestStageCMarkerlessCancellationCanRedispatchOrdinaryCandidate(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	local := startProviderInvocation(
		context.Background(), client,
		&types.OpenAIChatRequest{Model: "model-a"}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model-a", Provider: "provider-a", EndpointID: "snapshot"}},
		true, nil, "stage-c-unmarked-test",
	)
	<-local.selectedRoute.Ready()
	local.abort(errors.New("unmarked authorization"))
	<-local.done
	ordinary := startProviderInvocation(
		context.Background(), client,
		&types.OpenAIChatRequest{Model: "model-b"}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model-b", Provider: "provider-b", EndpointID: "ordinary"}},
		true, nil, "stage-c-unmarked-test",
	)
	body, err := io.ReadAll(ordinary.reader)
	if err != nil || string(body) != providerStreamTestResponse {
		t.Fatalf("ordinary redispatch body=%q err=%v", body, err)
	}
	<-ordinary.done
	if got := strings.Join(client.endpoints(), ","); got != "snapshot,ordinary" {
		t.Fatalf("candidate attempts=%q", got)
	}
}

// Mutation guard: deleting the err==nil/zero-byte conversion in
// invokeProviderStream makes this test stop after the first candidate.
func TestInvokeProviderStreamEmptySuccessFallsBack(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, out io.Writer) error {
		if option.EndpointID == "empty" {
			return nil
		}
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	options := []llm.InvokeOptions{
		{Model: "model-a", Provider: "provider-a", EndpointID: "empty"},
		{Model: "model-b", Provider: "provider-b", EndpointID: "success"},
	}

	body, err, selected := runProviderStreamTest(t, client, options)
	if err != nil {
		t.Fatalf("invokeProviderStream: %v", err)
	}
	if string(body) != providerStreamTestResponse {
		t.Fatalf("body = %q, want normal fallback response", body)
	}
	if got := strings.Join(client.endpoints(), ","); got != "empty,success" {
		t.Fatalf("attempt endpoints = %q, want empty,success", got)
	}
	if got := selected.Endpoint("", nil); got != "success" {
		t.Fatalf("selected endpoint = %q, want success", got)
	}
}

func TestInvokeProviderStreamEmptySuccessFailsWhenCandidatesExhausted(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(llm.InvokeOptions, io.Writer) error {
		return nil
	}}
	options := []llm.InvokeOptions{
		{Model: "model-a", Provider: "provider-a", EndpointID: "empty-a"},
		{Model: "model-b", Provider: "provider-b", EndpointID: "empty-b"},
	}

	body, err, _ := runProviderStreamTest(t, client, options)
	if len(body) != 0 {
		t.Fatalf("body = %q, want empty failed response", body)
	}
	if !errors.Is(err, errEmptyUpstreamResponse) {
		t.Fatalf("error = %v, want empty upstream response", err)
	}
	if got := strings.Join(client.endpoints(), ","); got != "empty-a,empty-b" {
		t.Fatalf("attempt endpoints = %q, want empty-a,empty-b", got)
	}
}

func TestInvokeProviderStreamEmptySuccessRespectsTransientRetryCap(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(llm.InvokeOptions, io.Writer) error {
		return nil
	}}
	oldSleep := sleepBeforeTransientRetry
	sleepBeforeTransientRetry = func(time.Duration) {}
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })

	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		invokeProviderStream(
			context.Background(), client,
			&types.OpenAIChatRequest{Model: "model-a"},
			&types.AnthropicMessagesRequest{}, pw,
			[]llm.InvokeOptions{{Model: "model-a", EndpointID: "empty"}},
			true, nil, newSelectedRouteTracker(), "retry-cap-test", true, true,
		)
	}()
	_, err := io.ReadAll(pr)
	<-done

	if !errors.Is(err, errEmptyUpstreamResponse) {
		t.Fatalf("error = %v, want empty upstream response", err)
	}
	if got, want := len(client.endpoints()), maxTransientUpstreamRetries+1; got != want {
		t.Fatalf("attempt count = %d, want initial try plus %d retries", got, maxTransientUpstreamRetries)
	}
}

func TestInvokeProviderStreamNormalResponsePasses(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}

	body, err, _ := runProviderStreamTest(t, client, []llm.InvokeOptions{{Model: "model-a", EndpointID: "normal"}})
	if err != nil {
		t.Fatalf("invokeProviderStream: %v", err)
	}
	if string(body) != providerStreamTestResponse {
		t.Fatalf("body = %q, want normal response", body)
	}
}

func TestInvokeProviderStreamDoesNotFallbackAfterFirstByte(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, out io.Writer) error {
		if option.EndpointID == "partial" {
			if _, err := io.WriteString(out, "x"); err != nil {
				return err
			}
			return errors.New("provider stream failed after output")
		}
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	options := []llm.InvokeOptions{
		{Model: "model-a", Provider: "provider-a", EndpointID: "partial"},
		{Model: "model-b", Provider: "provider-b", EndpointID: "must-not-run"},
	}

	body, err, _ := runProviderStreamTest(t, client, options)
	if string(body) != "x" {
		t.Fatalf("body = %q, want first provider byte only", body)
	}
	if err == nil || !strings.Contains(err.Error(), "failed after output") {
		t.Fatalf("error = %v, want post-output provider failure", err)
	}
	if got := strings.Join(client.endpoints(), ","); got != "partial" {
		t.Fatalf("attempt endpoints = %q, want no post-output fallback", got)
	}
}

func TestInvokeProviderStreamDoesNotFallbackAfterCommittedWriteReturnsZero(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, "provider output")
		return err
	}}
	options := []llm.InvokeOptions{
		{Model: "model-a", Provider: "provider-a", EndpointID: "committed"},
		{Model: "model-b", Provider: "provider-b", EndpointID: "must-not-run"},
	}
	pr, pw := io.Pipe()
	_ = pr.CloseWithError(errors.New("client stopped reading after response head"))

	invokeProviderStream(
		context.Background(), client,
		&types.OpenAIChatRequest{Model: "requested-model"},
		&types.AnthropicMessagesRequest{}, pw, options,
		true, nil, newSelectedRouteTracker(), "zero-write-test", false, false,
	)

	if got := strings.Join(client.endpoints(), ","); got != "committed" {
		t.Fatalf("attempt endpoints = %q, want no fallback after output was committed", got)
	}
}

func TestInvokeProviderStreamSwallowedZeroByteWriteFailsWithoutFallback(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, _ = io.WriteString(out, "provider output")
		return nil
	}}
	options := []llm.InvokeOptions{
		{Model: "model-a", Provider: "provider-a", EndpointID: "committed"},
		{Model: "model-b", Provider: "provider-b", EndpointID: "must-not-run"},
	}
	pr, pw := io.Pipe()
	_ = pr.CloseWithError(errors.New("client stopped reading after response head"))

	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		invokeProviderStream(
			context.Background(), client,
			&types.OpenAIChatRequest{Model: "requested-model"},
			&types.AnthropicMessagesRequest{}, pw, options,
			true, nil, newSelectedRouteTracker(), "swallowed-write-test", false, false,
		)
		return nil // invokeProviderStream runs synchronously here.
	})

	if got := strings.Join(client.endpoints(), ","); got != "committed" {
		t.Fatalf("attempt endpoints = %q, want no fallback after output was committed", got)
	}
	if !strings.Contains(logs, `outcome=fail`) || !strings.Contains(logs, `last_err="empty upstream response"`) {
		t.Fatalf("logs = %q, want failed empty-upstream completion", logs)
	}
}

// fn must start any provider invocation inside the capture scope and return it
// after serving the stream. Return nil only for synchronous provider calls.
func captureProviderStreamStderr(t *testing.T, fn func() *providerInvocation) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stderr-")
	if err != nil {
		t.Fatalf("capture stderr: %v", err)
	}
	defer file.Close()
	stderrFD := int(os.Stderr.Fd())
	originalFD, err := syscall.Dup(stderrFD)
	if err != nil {
		t.Fatalf("duplicate stderr: %v", err)
	}
	defer syscall.Close(originalFD)
	restored := false
	restore := func() {
		if !restored {
			if err := syscall.Dup2(originalFD, stderrFD); err != nil {
				t.Errorf("restore stderr: %v", err)
			}
			restored = true
		}
	}
	defer restore()
	// Other requests can finish logging after their tests return. Redirect the
	// descriptor, never the shared os.Stderr pointer those goroutines read.
	if err := syscall.Dup2(int(file.Fd()), stderrFD); err != nil {
		t.Fatalf("redirect stderr: %v", err)
	}

	if invocation := fn(); invocation != nil {
		// serveStreaming cancels the provider on return, but its final stderr
		// writes can still be in flight. Join it before restoring stderr.
		select {
		case <-invocation.done:
		case <-time.After(5 * time.Second):
			t.Fatal("provider invocation did not finish before restoring captured stderr")
		}
	}
	restore()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind captured stderr: %v", err)
	}
	captured, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(captured)
}

func TestCaptureProviderStreamStderrKeepsProcessPointerStable(t *testing.T) {
	original := os.Stderr
	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		if os.Stderr != original {
			t.Fatal("capture replaced os.Stderr while unrelated providers may still be logging")
		}
		_, _ = io.WriteString(os.Stderr, "stable stderr pointer\n")
		return nil
	})
	if !strings.Contains(logs, "stable stderr pointer\n") {
		t.Fatalf("missing captured log: %q", logs)
	}
}

func TestCaptureProviderStreamStderrWaitsForProviderCompletion(t *testing.T) {
	streamReturned := make(chan struct{})
	const lateLog = "provider log after serveStreaming returned\n"
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		_, err := io.WriteString(out, providerStreamTestResponse)
		// Hold the invocation open until serveStreaming has returned, then log
		// from that goroutine to exercise the capture helper's completion wait.
		<-streamReturned
		_, _ = io.WriteString(os.Stderr, lateLog)
		return err
	}}
	var out bytes.Buffer
	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		ctx := t.Context()
		req := &types.OpenAIChatRequest{Model: "model-a", Stream: true}
		anthropicReq := &types.AnthropicMessagesRequest{}
		options := []llm.InvokeOptions{{Model: "model-a", EndpointID: "normal"}}
		invocation := startProviderInvocation(ctx, client, req, anthropicReq, options, false, nil, "capture-wait-test")
		// Also join during cleanup so removing the helper's wait as a negative
		// control still lets the detector observe the late log before test exit.
		t.Cleanup(func() {
			select {
			case <-invocation.done:
			case <-time.After(5 * time.Second):
				t.Error("provider invocation did not finish during cleanup")
			}
		})
		serveStreaming(withProviderInvocation(ctx, invocation), &out, client,
			req, anthropicReq, options, nil, nil, nil, time.Now(), nil,
			"chat.completions", "capture-wait-test", "model-a")
		close(streamReturned)
		return invocation
	})
	if !strings.Contains(logs, lateLog) || !strings.Contains(logs, "enclave.invoke_complete") {
		t.Fatalf("logs = %q, want provider logs emitted after serveStreaming returned", logs)
	}
}

func TestServeStreamingDoesNotWriteSuccessHeadBeforeProviderFirstByte(t *testing.T) {
	client := &blockingFirstByteClient{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	out := &synchronizedBuffer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveStreaming(
			context.Background(), out, client,
			&types.OpenAIChatRequest{Model: "model-a", Stream: true},
			&types.AnthropicMessagesRequest{},
			[]llm.InvokeOptions{{Model: "model-a", EndpointID: "normal"}},
			nil, nil, nil, time.Now(), nil,
			"chat.completions", "head-boundary-test", "model-a",
		)
	}()

	<-client.started
	if got := out.Len(); got != 0 {
		t.Fatalf("response bytes before provider first byte = %d, want 0", got)
	}
	close(client.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveStreaming did not finish")
	}
	if got := out.String(); !strings.Contains(got, "HTTP/1.1 200 OK") || !strings.Contains(got, "data: [DONE]") {
		t.Fatalf("completed stream = %q, want success head and terminal event", got)
	}
}

func TestStageCProviderPipeBlocksFirstByteUntilReserveGate(t *testing.T) {
	started := make(chan struct{})
	writeReturned := make(chan struct{})
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		close(started)
		_, err := io.WriteString(out, providerStreamTestResponse)
		close(writeReturned)
		return err
	}}
	invocation := startProviderInvocation(
		context.Background(), client,
		&types.OpenAIChatRequest{Model: "model-a"}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model-a", EndpointID: "endpoint-a"}}, true, nil, "stage-c-gate-test",
	)
	defer invocation.cancel()
	<-started
	select {
	case <-writeReturned:
		t.Fatal("provider first byte passed the unbuffered gate before reserve resolution")
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := io.ReadAll(invocation.reader); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeReturned:
	case <-time.After(time.Second):
		t.Fatal("provider did not finish after the gate opened")
	}
}

func TestStageCRejectedReserveCancelsSpeculativeProvider(t *testing.T) {
	client := &stageCCancelClient{started: make(chan struct{}), done: make(chan struct{})}
	invocation := startProviderInvocation(
		context.Background(), client,
		&types.OpenAIChatRequest{Model: "model-a"}, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: "model-a", EndpointID: "endpoint-a"}}, true, nil, "stage-c-cancel-test",
	)
	<-client.started
	invocation.abort(errors.New("admission_rejected"))
	select {
	case <-client.done:
	case <-time.After(time.Second):
		t.Fatal("speculative provider was not cancelled on reserve rejection")
	}
}

func TestServeStreamingEmptyProviderDoesNotDeadlockBeforeHead(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(llm.InvokeOptions, io.Writer) error {
		return nil
	}}
	out := &synchronizedBuffer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveStreaming(
			context.Background(), out, client,
			&types.OpenAIChatRequest{Model: "model-a", Stream: true},
			&types.AnthropicMessagesRequest{},
			[]llm.InvokeOptions{
				{Model: "model-a", EndpointID: "empty"},
				{Model: "model-b", EndpointID: "unused-without-router"},
			},
			nil, nil, nil, time.Now(), nil,
			"chat.completions", "empty-head-test", "model-a",
		)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveStreaming deadlocked before reading the provider failure")
	}
	if got := out.String(); !strings.Contains(got, "HTTP/1.1 200 OK") || !strings.Contains(got, "empty upstream response") {
		t.Fatalf("failed stream = %q, want legacy SSE provider failure", got)
	}
}

func TestInvokeProviderStreamRetryPhaseTimings(t *testing.T) {
	clock := &phaseAuditClock{now: time.Unix(1000, 0)}
	phases := requesttiming.New(clock.Now(), clock.Now)
	phases.Start()
	attempts, sleeps := 0, 0
	client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		attempts++
		clock.advance(100)
		if attempts == 1 {
			return io.ErrUnexpectedEOF
		}
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	oldSleep := sleepBeforeTransientRetry
	sleepBeforeTransientRetry = func(wait time.Duration) {
		sleeps++
		if wait != time.Second {
			t.Errorf("retry wait=%s, want 1s", wait)
		}
		clock.advance(1000)
	}
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	pr, pw := io.Pipe()
	defer pr.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		invokeProviderStream(requesttiming.WithTimer(t.Context(), phases), client,
			&types.OpenAIChatRequest{Model: "model-a"}, &types.AnthropicMessagesRequest{}, pw,
			[]llm.InvokeOptions{{Model: "model-a", EndpointID: "retry"}},
			true, nil, newSelectedRouteTracker(), "retry-timing-test", true, true)
	}()
	body, err := io.ReadAll(pr)
	<-done
	if err != nil || string(body) != providerStreamTestResponse || attempts != 2 || sleeps != 1 {
		t.Fatalf("response=%q err=%v attempts=%d sleeps=%d", body, err, attempts, sleeps)
	}
	elapsed := phases.End()
	f := phases.Snapshot()
	if f.UpstreamMS != 200 || f.RetryWaitMS != 1000 || f.RouteMS != 0 || f.ReceiptMS != 0 || f.UpstreamPartial != 0 || f.TTFBMS != 100 || elapsed != 1200*time.Millisecond {
		t.Fatalf("retry phases=%+v elapsed=%s", f, elapsed)
	}
	sum := f.AcceptToStartMS + f.AuthorizeMS + f.RouteMS + f.UpstreamMS + f.RetryWaitMS + f.SettleMS + f.ReceiptMS
	if sum != elapsed.Milliseconds() {
		t.Fatalf("phase sum=%d elapsed=%s", sum, elapsed)
	}
	var log bytes.Buffer
	writeRequestEndLog(&log, "retry-timing-test", "POST", "/v1/chat/completions", 200, 0, len(body), elapsed, requestAuditIdentity{}, "ok", f)
	if got := parseAuditEvent(t, log.String(), "enclave.request_end")["retry_wait_ms"]; got != "1000" {
		t.Fatalf("logged retry_wait_ms=%q", got)
	}
}

// Fusion panels and Combo calls through Fusion share a context while invoking
// this wrapper concurrently. Keep both provider lifetimes under
// explicit control so the request can end with B still running.
func TestInvokeProviderStreamOverlappingPhaseTimings(t *testing.T) {
	clock := &phaseAuditClock{now: time.Unix(1000, 0)}
	phases := requesttiming.New(clock.Now(), clock.Now)
	phases.Start()
	ctx := requesttiming.WithTimer(t.Context(), phases)
	startedA, startedB := make(chan struct{}), make(chan struct{})
	writeA, wroteA := make(chan struct{}), make(chan struct{})
	finishA, finishB := make(chan struct{}), make(chan struct{})
	type response struct {
		body string
		err  error
	}
	responses := make(chan response, 2)
	start := func(client *scriptedProviderStreamClient) <-chan struct{} {
		pr, pw := io.Pipe()
		go func() {
			defer pr.Close()
			body, err := io.ReadAll(pr)
			responses <- response{string(body), err}
		}()
		done := make(chan struct{})
		go func() {
			defer close(done)
			invokeProviderStream(ctx, client, &types.OpenAIChatRequest{Model: "model-a"},
				&types.AnthropicMessagesRequest{}, pw,
				[]llm.InvokeOptions{{Model: "model-a"}}, true, nil,
				newSelectedRouteTracker(), "overlap-timing-test", true, false)
		}()
		return done
	}
	doneA := start(&scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		close(startedA)
		<-writeA
		_, err := io.WriteString(out, providerStreamTestResponse)
		close(wroteA)
		<-finishA
		return err
	}})
	<-startedA
	clock.advance(10)
	doneB := start(&scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, out io.Writer) error {
		close(startedB)
		<-finishB
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}})
	<-startedB
	clock.advance(10)
	close(writeA)
	<-wroteA
	clock.advance(10)
	close(finishA)
	<-doneA
	clock.advance(10)
	elapsed := phases.End()
	before := phases.Snapshot()
	clock.advance(100)
	close(finishB)
	<-doneB
	for i := 0; i < 2; i++ {
		got := <-responses
		if got.err != nil || got.body != providerStreamTestResponse {
			t.Fatalf("response=%q err=%v", got.body, got.err)
		}
	}
	if before.UpstreamMS != 40 || before.TTFBMS != 20 || before.UpstreamPartial != 1 || before.ReceiptMS != 0 || elapsed != 40*time.Millisecond {
		t.Fatalf("overlapping provider calls=%+v elapsed=%s", before, elapsed)
	}
	if after := phases.Snapshot(); after != before || phases.End() != elapsed {
		t.Fatalf("late completion changed snapshot: %+v -> %+v", before, after)
	}
}
