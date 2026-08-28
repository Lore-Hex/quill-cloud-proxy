package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
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

	logs := captureProviderStreamStderr(t, func() {
		invokeProviderStream(
			context.Background(), client,
			&types.OpenAIChatRequest{Model: "requested-model"},
			&types.AnthropicMessagesRequest{}, pw, options,
			true, nil, newSelectedRouteTracker(), "swallowed-write-test", false, false,
		)
	})

	if got := strings.Join(client.endpoints(), ","); got != "committed" {
		t.Fatalf("attempt endpoints = %q, want no fallback after output was committed", got)
	}
	if !strings.Contains(logs, `outcome=fail`) || !strings.Contains(logs, `last_err="empty upstream response"`) {
		t.Fatalf("logs = %q, want failed empty-upstream completion", logs)
	}
}

func captureProviderStreamStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("capture stderr: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = oldStderr
		_ = r.Close()
		_ = w.Close()
	}()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close captured stderr: %v", err)
	}
	os.Stderr = oldStderr
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(captured)
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
