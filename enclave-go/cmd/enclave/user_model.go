package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	userModelSecretNamespace = "user_model"
	// AAD purpose labels, not credentials: they name WHICH secret an envelope
	// is bound to and are identical on both planes.
	userModelEndpointSecretPurpose = "user_model_endpoint_key" //nolint:gosec // G101: AAD label
	userModelSigningSecretPurpose  = "user_model_signing"      //nolint:gosec // G101: AAD label
	maxUserModelSSEEventBytes      = 1 << 20
	maxUserModelResponseBytes      = 64 << 20
)

var (
	userModelKeepaliveInterval = 15 * time.Second
	userModelNow               = time.Now
	newUserModelHTTPClient     = llm.NewGuardedHTTPClient
)

var userModelOwnerBodyAllowlist = map[string]struct{}{
	"messages": {}, "temperature": {}, "top_p": {}, "n": {}, "stop": {},
	"max_tokens": {}, "max_completion_tokens": {}, "presence_penalty": {},
	"frequency_penalty": {}, "logit_bias": {}, "logprobs": {}, "top_logprobs": {},
	"response_format": {}, "seed": {}, "tools": {}, "tool_choice": {},
	"parallel_tool_calls": {}, "reasoning_effort": {}, "metadata": {},
	"stream_options": {},
}

type userModelDispatchError struct {
	callerStatus int
	message      string
	refundStatus int
	refundType   string
	cause        error
}

func (e *userModelDispatchError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (e *userModelDispatchError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type malformedUserModelResponse struct{ reason string }

func (e *malformedUserModelResponse) Error() string {
	return "malformed user-model response: " + e.reason
}

type userModelDispatchState struct {
	startedAt time.Time
	requestID string
	firstByte chan struct{}
	once      sync.Once
	mu        sync.Mutex
	firstAt   time.Time
}

func newUserModelDispatchState() *userModelDispatchState {
	return &userModelDispatchState{startedAt: userModelNow(), firstByte: make(chan struct{})}
}

func (s *userModelDispatchState) markFirstByte() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.mu.Lock()
		s.firstAt = userModelNow()
		s.mu.Unlock()
		close(s.firstByte)
	})
}

func (s *userModelDispatchState) firstTokenSeconds() float64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	firstAt := s.firstAt
	s.mu.Unlock()
	if firstAt.IsZero() {
		return 0
	}
	return maxDurationSeconds(firstAt.Sub(s.startedAt), 0.001)
}

func (s *userModelDispatchState) elapsedSeconds() float64 {
	if s == nil {
		return 0.001
	}
	return maxDurationSeconds(userModelNow().Sub(s.startedAt), 0.001)
}

func isUserProvidedCustomModel(authorization *trustedrouter.Authorization) bool {
	return authorization != nil && authorization.CustomModel != nil &&
		strings.EqualFold(strings.TrimSpace(authorization.CustomModel.Kind), "user_provided")
}

func buildUserModelOwnerBody(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	rawCallerBody map[string]any,
	anthropicReq *types.AnthropicMessagesRequest,
	model *trustedrouter.CustomModel,
) ([]byte, error) {
	if req == nil || model == nil {
		return nil, errors.New("missing user-model request contract")
	}
	source := rawCallerBody
	if source == nil {
		var err error
		if anthropicReq != nil {
			source, err = llm.BuildOpenAICompatibleRequestShape(
				ctx, req, anthropicReq, model.UpstreamModelID, model.SupportsStreaming,
			)
			if err != nil {
				return nil, err
			}
		} else {
			encoded, marshalErr := json.Marshal(req)
			if marshalErr != nil {
				return nil, marshalErr
			}
			if err := json.Unmarshal(encoded, &source); err != nil {
				return nil, err
			}
		}
		// Responses keeps its OpenAI-compatible stream_options in the
		// response metadata rather than on the chat shim.
		if req.Response != nil && req.Response.StreamOptions != nil {
			source["stream_options"] = req.Response.StreamOptions
		}
		// The shared projection owns message/tool conversion, but it does not
		// carry every optional caller field. Merge only the public allowlist
		// from the decoded request so metadata, n, logprobs, and similar fields
		// survive Messages/Responses adaptation without exposing TR controls.
		encoded, marshalErr := json.Marshal(req)
		if marshalErr != nil {
			return nil, marshalErr
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return nil, err
		}
		for key, value := range decoded {
			if key == "messages" {
				continue
			}
			if _, allowed := userModelOwnerBodyAllowlist[key]; allowed {
				source[key] = value
			}
		}
	}
	body := make(map[string]any, len(userModelOwnerBodyAllowlist)+2)
	for key, value := range source {
		if _, allowed := userModelOwnerBodyAllowlist[key]; allowed {
			body[key] = value
		}
	}
	body["model"] = model.UpstreamModelID
	body["stream"] = model.SupportsStreaming
	if !model.SupportsStreaming {
		// Strict buffered owners reject stream-only controls. The shared native
		// projection injects this field, and chat callers may supply it directly,
		// so remove it after the owner capability has forced stream=false.
		delete(body, "stream_options")
	} else if _, present := body["stream_options"]; !present {
		// Streaming owners should report usage even when the caller did not ask
		// for it; real counts are preferable to settlement estimates.
		body["stream_options"] = map[string]any{"include_usage": true}
	}
	return json.Marshal(body)
}

func signUserModelRequest(secret string, body []byte, now time.Time) string {
	timestamp := now.Unix()
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%d.", timestamp)
	_, _ = mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
}

func dispatchUserModel(
	ctx context.Context,
	state *userModelDispatchState,
	req *types.OpenAIChatRequest,
	rawCallerBody map[string]any,
	anthropicReq *types.AnthropicMessagesRequest,
	model *trustedrouter.CustomModel,
	secretCache *byokcache.Cache,
	out io.Writer,
) error {
	if state == nil {
		state = newUserModelDispatchState()
	}
	if err := validateUserModelContract(model, secretCache); err != nil {
		return internalUserModelError(err)
	}

	signingSecret, _, err := secretCache.ResolveUserModel(
		ctx, model.OwnerWorkspaceID, model.SigningSecretPurpose, *model.SigningEncryptedSecret,
	)
	if err != nil {
		return internalUserModelError(err)
	}
	endpointKey := ""
	if model.EndpointEncryptedSecret != nil {
		endpointKey, _, err = secretCache.ResolveUserModel(
			ctx, model.OwnerWorkspaceID, model.EndpointSecretPurpose, *model.EndpointEncryptedSecret,
		)
		if err != nil {
			return internalUserModelError(err)
		}
	}
	body, err := buildUserModelOwnerBody(ctx, req, rawCallerBody, anthropicReq, model)
	if err != nil {
		return internalUserModelError(err)
	}

	requestURL := strings.TrimRight(model.EndpointURL, "/") + "/chat/completions"
	connectTimeout := time.Duration(model.ConnectTimeoutSeconds) * time.Second
	firstByteTimeout := time.Duration(model.FirstByteTimeoutSeconds) * time.Second
	idleTimeout := time.Duration(model.IdleTimeoutSeconds) * time.Second
	totalTimeout := time.Duration(model.TotalTimeoutSeconds) * time.Second
	remainingFirstByte := firstByteTimeout - userModelNow().Sub(state.startedAt)
	if remainingFirstByte <= 0 {
		return timeoutUserModelError(model, context.DeadlineExceeded)
	}
	httpClient, err := newUserModelHTTPClient(requestURL, llm.EgressGuardOptions{
		ConnectTimeout:        connectTimeout,
		ResponseHeaderTimeout: remainingFirstByte,
		IdleTimeout:           idleTimeout,
		TotalTimeout:          totalTimeout,
	})
	if err != nil {
		return connectionUserModelError(model, err)
	}
	// Guarded clients own a per-dispatch Transport. Close its pool when this
	// generation ends so untrusted owners cannot accumulate idle connections.
	defer httpClient.CloseIdleConnections()

	totalCtx, cancelTotal := context.WithDeadline(ctx, state.startedAt.Add(totalTimeout))
	defer cancelTotal()
	httpReq, err := http.NewRequestWithContext(totalCtx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return internalUserModelError(err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream, application/json")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")
	httpReq.Header.Set("TR-Signature", signUserModelRequest(signingSecret, body, userModelNow()))
	if endpointKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+endpointKey)
	}

	response, err := doUserModelRequestBefore(
		totalCtx, cancelTotal, httpClient, httpReq, state.startedAt.Add(firstByteTimeout),
	)
	if err != nil {
		var guardErr *llm.EgressGuardError
		var dialErr *llm.EgressDialError
		if errors.As(err, &guardErr) || errors.As(err, &dialErr) || strings.Contains(err.Error(), "TLS handshake timeout") {
			return connectionUserModelError(model, err)
		}
		var netErr net.Error
		if errors.Is(err, errUserModelFirstByteTimeout) || errors.Is(totalCtx.Err(), context.DeadlineExceeded) ||
			(errors.As(err, &netErr) && netErr.Timeout()) {
			return timeoutUserModelError(model, err)
		}
		if errors.Is(totalCtx.Err(), context.Canceled) && ctx.Err() != nil {
			return clientClosedUserModelError(ctx.Err())
		}
		return connectionUserModelError(model, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return upstreamStatusUserModelError(model, response.StatusCode)
	}

	// Bound total bytes as a second line of defense behind the per-event cap.
	// LimitReader prevents an endless sequence of small, valid SSE lines from
	// consuming an unbounded amount of enclave work or retained buffers.
	ownerBody := limitUserModelResponse(response.Body, maxUserModelResponseBytes)
	first, err := readFirstUserModelBytes(
		totalCtx, cancelTotal, ownerBody, state.startedAt.Add(firstByteTimeout),
	)
	if err != nil {
		if errors.Is(err, errUserModelFirstByteTimeout) || errors.Is(totalCtx.Err(), context.DeadlineExceeded) {
			return timeoutUserModelError(model, err)
		}
		if ctx.Err() != nil {
			return clientClosedUserModelError(ctx.Err())
		}
		return malformedUserModelError(model, err)
	}
	state.markFirstByte()
	reader := io.MultiReader(bytes.NewReader(first), ownerBody)
	if model.SupportsStreaming {
		err = translateUserModelSSE(reader, out)
	} else {
		err = translateUserModelBuffered(reader, out, model.ID, state.requestID)
	}
	if err == nil {
		return nil
	}
	if ctx.Err() != nil || errors.Is(err, io.ErrClosedPipe) {
		return clientClosedUserModelError(err)
	}
	var netErr net.Error
	if errors.Is(totalCtx.Err(), context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return timeoutUserModelError(model, err)
	}
	var malformed *malformedUserModelResponse
	if errors.As(err, &malformed) {
		return malformedUserModelError(model, err)
	}
	if errors.As(err, &netErr) {
		return connectionUserModelError(model, err)
	}
	return internalUserModelError(err)
}

func limitUserModelResponse(body io.Reader, maxBytes int64) io.Reader {
	// Retain one byte beyond the budget so downstream parsers cannot mistake a
	// truncated, exactly-at-the-cap response for a naturally terminated body.
	return io.LimitReader(body, maxBytes+1)
}

func validateUserModelContract(model *trustedrouter.CustomModel, secretCache *byokcache.Cache) error {
	if model == nil || !strings.EqualFold(strings.TrimSpace(model.Kind), "user_provided") {
		return errors.New("missing user-provided model dispatch block")
	}
	if secretCache == nil || strings.TrimSpace(model.ID) == "" || strings.TrimSpace(model.OwnerWorkspaceID) == "" ||
		strings.TrimSpace(model.EndpointURL) == "" || strings.TrimSpace(model.UpstreamModelID) == "" {
		return errors.New("incomplete user-model dispatch block")
	}
	if model.SecretNamespace != userModelSecretNamespace || model.SigningSecretPurpose != userModelSigningSecretPurpose ||
		model.SigningEncryptedSecret == nil {
		return errors.New("invalid user-model signing-secret contract")
	}
	if model.EndpointEncryptedSecret != nil && model.EndpointSecretPurpose != userModelEndpointSecretPurpose {
		return errors.New("invalid user-model endpoint-secret contract")
	}
	if model.ConnectTimeoutSeconds <= 0 || model.FirstByteTimeoutSeconds <= 0 ||
		model.IdleTimeoutSeconds <= 0 || model.TotalTimeoutSeconds <= 0 {
		return errors.New("invalid user-model dispatch budget")
	}
	return nil
}

var errUserModelFirstByteTimeout = errors.New("user-model first-byte budget exceeded")

type userModelHTTPResult struct {
	response *http.Response
	err      error
}

func doUserModelRequestBefore(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	req *http.Request,
	deadline time.Time,
) (*http.Response, error) {
	remaining := deadline.Sub(userModelNow())
	if remaining <= 0 {
		return nil, errUserModelFirstByteTimeout
	}
	result := make(chan userModelHTTPResult, 1)
	go func() {
		response, err := client.Do(req)
		result <- userModelHTTPResult{response: response, err: err}
	}()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case completed := <-result:
		return completed.response, completed.err
	case <-timer.C:
		cancel()
		go closeLateUserModelResponse(result)
		return nil, errUserModelFirstByteTimeout
	case <-ctx.Done():
		cancel()
		go closeLateUserModelResponse(result)
		return nil, ctx.Err()
	}
}

func closeLateUserModelResponse(result <-chan userModelHTTPResult) {
	completed := <-result
	if completed.response != nil {
		completed.response.Body.Close()
	}
}

type userModelReadResult struct {
	bytes []byte
	err   error
}

func readFirstUserModelBytes(
	ctx context.Context,
	cancel context.CancelFunc,
	body io.Reader,
	deadline time.Time,
) ([]byte, error) {
	remaining := deadline.Sub(userModelNow())
	if remaining <= 0 {
		return nil, errUserModelFirstByteTimeout
	}
	result := make(chan userModelReadResult, 1)
	go func() {
		buffer := make([]byte, 32*1024)
		n, err := body.Read(buffer)
		result <- userModelReadResult{bytes: buffer[:n], err: err}
	}()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case completed := <-result:
		if len(completed.bytes) == 0 {
			if completed.err == nil {
				return nil, &malformedUserModelResponse{reason: "empty owner response"}
			}
			return nil, completed.err
		}
		return completed.bytes, nil
	case <-timer.C:
		cancel()
		return nil, errUserModelFirstByteTimeout
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

func translateUserModelSSE(r io.Reader, w io.Writer) error {
	// Scanner refuses an overlong token as soon as the fixed line cap is hit;
	// unlike Reader.ReadBytes it never grows a slice until an attacker finally
	// supplies a newline.
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxUserModelSSEEventBytes)
	var event bytes.Buffer
	sawChunk := false
	sawDone := false
	stopReason := "end_turn"
	toolCalls := map[int]bool{}
	var toolOrder []int
	var usage map[string]any

	process := func(raw []byte) error {
		payload := userModelSSEData(raw)
		if payload == nil {
			return nil
		}
		if bytes.Equal(payload, []byte("[DONE]")) {
			sawDone = true
			return nil
		}
		var chunk struct {
			Object  string               `json:"object"`
			Choices []userModelSSEChoice `json:"choices"`
			Usage   map[string]any       `json:"usage"`
		}
		if err := json.Unmarshal(payload, &chunk); err != nil || chunk.Object != "chat.completion.chunk" {
			return &malformedUserModelResponse{reason: "invalid owner SSE JSON"}
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			// Empty choice chunks are harmless provider metadata/heartbeats. Usage
			// is optional on that shape in the control-plane reference dispatcher.
			return nil
		}
		sawChunk = true
		choice := chunk.Choices[0]
		if choice.Delta.Content != nil {
			content, ok := choice.Delta.Content.(string)
			if !ok {
				return &malformedUserModelResponse{reason: "invalid owner SSE content"}
			}
			if content != "" {
				if err := writeUserModelTextDelta(w, content); err != nil {
					return err
				}
			}
		}
		for _, delta := range choice.Delta.ToolCalls {
			// Text deltas occupy internal content-block index zero. Reserve it
			// even for tool-only streams so a later text delta cannot collide.
			internalIndex := delta.Index + 1
			if !toolCalls[delta.Index] {
				toolCalls[delta.Index] = true
				toolOrder = append(toolOrder, internalIndex)
				id := delta.ID
				if id == "" {
					id = fmt.Sprintf("call_%d", delta.Index)
				}
				if err := writeUserModelToolStart(w, internalIndex, id, delta.Function.Name); err != nil {
					return err
				}
			}
			if delta.Function.Arguments != "" {
				if err := writeUserModelToolDelta(w, internalIndex, delta.Function.Arguments); err != nil {
					return err
				}
			}
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			stopReason = userModelAnthropicStopReason(*choice.FinishReason)
		}
		return nil
	}

	for !sawDone && scanner.Scan() {
		line := bytes.TrimSuffix(scanner.Bytes(), []byte("\r"))
		if len(line) == 0 {
			if err := process(event.Bytes()); err != nil {
				return err
			}
			event.Reset()
		} else {
			event.Write(line)
			event.WriteByte('\n')
			if event.Len() > maxUserModelSSEEventBytes {
				return &malformedUserModelResponse{reason: "owner SSE event is too large"}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return &malformedUserModelResponse{reason: "owner SSE line is too large"}
	}
	if !sawDone && event.Len() > 0 {
		if err := process(event.Bytes()); err != nil {
			return err
		}
	}
	if !sawChunk || !sawDone {
		return &malformedUserModelResponse{reason: "owner stream was incomplete"}
	}
	for _, index := range toolOrder {
		if err := writeUserModelToolStop(w, index); err != nil {
			return err
		}
	}
	return writeUserModelStop(w, stopReason, usage)
}

type userModelSSEChoice struct {
	Delta struct {
		Content   any `json:"content"`
		ToolCalls []struct {
			Index    int    `json:"index"`
			ID       string `json:"id"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	} `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

func userModelSSEData(event []byte) []byte {
	var values [][]byte
	for _, line := range bytes.Split(event, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("data:")) {
			values = append(values, bytes.TrimSpace(line[len("data:"):]))
		}
	}
	if len(values) == 0 {
		return nil
	}
	return bytes.Join(values, []byte("\n"))
}

func translateUserModelBuffered(r io.Reader, w io.Writer, responseModel, requestID string) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxRequestBodyBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxRequestBodyBytes {
		return &malformedUserModelResponse{reason: "owner response is too large"}
	}
	var completion struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Role      string                 `json:"role"`
				Content   any                    `json:"content"`
				ToolCalls []types.OpenAIToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(raw, &completion); err != nil || completion.Object != "chat.completion" || len(completion.Choices) == 0 {
		return &malformedUserModelResponse{reason: "invalid owner chat completion"}
	}
	choice := completion.Choices[0]
	content := ""
	if choice.Message.Content != nil {
		var ok bool
		content, ok = choice.Message.Content.(string)
		if !ok {
			return &malformedUserModelResponse{reason: "invalid owner message content"}
		}
	}
	inputTokens := userModelUsageInt(completion.Usage, "prompt_tokens")
	outputTokens := userModelUsageInt(completion.Usage, "completion_tokens")
	messageID := requestID
	if messageID == "" {
		messageID = newMessageID()
	}
	// The owner completion id belongs outside the TrustedRouter response
	// namespace. In particular, /v1/messages may relay message_start verbatim,
	// so always bind that id to the enclave-generated request id.
	if err := writeUserModelEvent(w, "message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": messageID, "type": "message", "role": "assistant", "model": responseModel,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]int{"input_tokens": inputTokens, "output_tokens": 0},
		},
	}); err != nil {
		return err
	}
	index := 0
	if content != "" || len(choice.Message.ToolCalls) == 0 {
		if err := writeUserModelEvent(w, "content_block_start", map[string]any{
			"type": "content_block_start", "index": index,
			"content_block": map[string]any{"type": "text", "text": ""},
		}); err != nil {
			return err
		}
		if err := writeUserModelTextDeltaAt(w, index, content); err != nil {
			return err
		}
		if err := writeUserModelEvent(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": index}); err != nil {
			return err
		}
		index++
	}
	for _, call := range choice.Message.ToolCalls {
		if call.Function.Name == "" {
			return &malformedUserModelResponse{reason: "invalid owner tool call"}
		}
		id := call.ID
		if id == "" {
			id = fmt.Sprintf("call_%d", index)
		}
		if err := writeUserModelToolStart(w, index, id, call.Function.Name); err != nil {
			return err
		}
		if err := writeUserModelToolDelta(w, index, call.Function.Arguments); err != nil {
			return err
		}
		if err := writeUserModelToolStop(w, index); err != nil {
			return err
		}
		index++
	}
	stopReason := "end_turn"
	if choice.FinishReason != nil {
		stopReason = userModelAnthropicStopReason(*choice.FinishReason)
	}
	return writeUserModelStop(w, stopReason, map[string]any{
		"prompt_tokens": inputTokens, "completion_tokens": outputTokens,
	})
}

func writeUserModelTextDelta(w io.Writer, text string) error {
	return writeUserModelTextDeltaAt(w, 0, text)
}

func writeUserModelTextDeltaAt(w io.Writer, index int, text string) error {
	return writeUserModelEvent(w, "content_block_delta", map[string]any{
		"type": "content_block_delta", "index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
}

func writeUserModelToolStart(w io.Writer, index int, id, name string) error {
	return writeUserModelEvent(w, "content_block_start", map[string]any{
		"type": "content_block_start", "index": index,
		"content_block": map[string]any{"type": "tool_use", "id": id, "name": name, "input": map[string]any{}},
	})
}

func writeUserModelToolDelta(w io.Writer, index int, arguments string) error {
	return writeUserModelEvent(w, "content_block_delta", map[string]any{
		"type": "content_block_delta", "index": index,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": arguments},
	})
}

func writeUserModelToolStop(w io.Writer, index int) error {
	return writeUserModelEvent(w, "content_block_stop", map[string]any{
		"type": "content_block_stop", "index": index,
	})
}

func writeUserModelStop(w io.Writer, stopReason string, usage map[string]any) error {
	messageUsage := map[string]any{}
	if usage != nil {
		messageUsage["input_tokens"] = userModelUsageInt(usage, "prompt_tokens")
		messageUsage["output_tokens"] = userModelUsageInt(usage, "completion_tokens")
		if details, ok := usage["completion_tokens_details"].(map[string]any); ok {
			if reasoning := userModelUsageInt(details, "reasoning_tokens"); reasoning > 0 {
				messageUsage["reasoning_tokens"] = reasoning
			}
		}
	}
	payload := map[string]any{
		"type": "message_delta", "delta": map[string]any{"stop_reason": stopReason},
	}
	if len(messageUsage) > 0 {
		payload["usage"] = messageUsage
	}
	if err := writeUserModelEvent(w, "message_delta", payload); err != nil {
		return err
	}
	return writeUserModelEvent(w, "message_stop", map[string]any{"type": "message_stop"})
}

func writeUserModelEvent(w io.Writer, event string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
	return err
}

func userModelUsageInt(usage map[string]any, key string) int {
	if usage == nil {
		return 0
	}
	switch value := usage[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func userModelAnthropicStopReason(reason string) string {
	switch reason {
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return types.SyntheticStopReasonContentFilter
	default:
		return "end_turn"
	}
}

func connectionUserModelError(model *trustedrouter.CustomModel, cause error) *userModelDispatchError {
	return &userModelDispatchError{
		callerStatus: 502, refundStatus: 502, refundType: "connection_error", cause: cause,
		message: fmt.Sprintf("User-provided model %s could not be reached", model.ID),
	}
}

func timeoutUserModelError(model *trustedrouter.CustomModel, cause error) *userModelDispatchError {
	return &userModelDispatchError{
		callerStatus: 504, refundStatus: 504, refundType: "user_model_timeout", cause: cause,
		message: fmt.Sprintf("User-provided %s model %s exceeded its dispatch budget", model.UserModelKind, model.ID),
	}
}

func upstreamStatusUserModelError(model *trustedrouter.CustomModel, status int) *userModelDispatchError {
	errorType := "upstream_client_error"
	if status >= 500 {
		errorType = "provider_error"
	}
	return &userModelDispatchError{
		callerStatus: 502, refundStatus: status, refundType: errorType,
		message: fmt.Sprintf("User-provided model %s returned an upstream error (HTTP %d)", model.ID, status),
	}
}

func malformedUserModelError(model *trustedrouter.CustomModel, cause error) *userModelDispatchError {
	return &userModelDispatchError{
		callerStatus: 502, refundStatus: 502, refundType: "malformed_response", cause: cause,
		message: fmt.Sprintf("User-provided model %s returned a malformed response", model.ID),
	}
}

func internalUserModelError(cause error) *userModelDispatchError {
	return &userModelDispatchError{
		callerStatus: 500, refundStatus: 500, refundType: "internal_error", cause: cause,
		message: "User-provided model dispatch failed inside the enclave",
	}
}

func clientClosedUserModelError(cause error) *userModelDispatchError {
	return &userModelDispatchError{
		callerStatus: 499, refundStatus: 499, refundType: "client_closed", cause: cause,
		message: "caller disconnected",
	}
}

func serveUserModel(
	ctx context.Context,
	conn io.Writer,
	req *types.OpenAIChatRequest,
	rawCallerBody map[string]any,
	anthropicReq *types.AnthropicMessagesRequest,
	routeType string,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	originalInput any,
	nativeMessages *adapter.AnthropicNativeRequest,
	requestLogID string,
) {
	if req == nil || !isUserProvidedCustomModel(authorization) {
		writeUserModelBufferedError(conn, routeType, internalUserModelError(errors.New("missing user-model authorization")))
		return
	}
	selectedRoute := newSelectedRouteTracker()
	option := llm.InvokeOptions{
		Model:      authorization.Model,
		Provider:   authorization.Provider,
		EndpointID: authorization.EndpointID,
		UsageType:  authorization.UsageType,
	}
	selectedRoute.Select(option)
	if req.Stream {
		serveUserModelStreaming(
			ctx, conn, req, rawCallerBody, anthropicReq, routeType, trGateway, authorization,
			secretCache, originalInput, selectedRoute, option, requestLogID,
		)
		return
	}
	serveUserModelBuffered(
		ctx, conn, req, rawCallerBody, anthropicReq, routeType, trGateway, authorization,
		secretCache, originalInput, nativeMessages, selectedRoute, option, requestLogID,
	)
}

func serveUserModelBuffered(
	ctx context.Context,
	conn io.Writer,
	req *types.OpenAIChatRequest,
	rawCallerBody map[string]any,
	anthropicReq *types.AnthropicMessagesRequest,
	routeType string,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	originalInput any,
	nativeMessages *adapter.AnthropicNativeRequest,
	selectedRoute *selectedRouteTracker,
	option llm.InvokeOptions,
	requestLogID string,
) {
	requestID := newUserModelRequestID(routeType)
	state := newUserModelDispatchState()
	state.requestID = requestID
	dispatchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientClosed := cancelUserModelOnDisconnect(dispatchCtx, cancel, conn)
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := dispatchUserModel(
			dispatchCtx, state, req, rawCallerBody, anthropicReq, authorization.CustomModel, secretCache, pw,
		)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	result, collectErr := adapter.CollectAnthropicText(pr)
	if collectErr != nil {
		cancel()
		_ = pr.CloseWithError(collectErr)
	}
	dispatchErr := <-done
	if clientClosed.Load() {
		// Buffered routes have not written any response body before settlement.
		// An owner first byte is not delivery to the caller, so a disconnected
		// caller must receive a 499 refund rather than a partial settlement.
		refundUserModel(ctx, trGateway, authorization, clientClosedUserModelError(context.Canceled), state, req.Metadata)
		return
	}
	if collectErr != nil || dispatchErr != nil {
		dispatchFailure := asUserModelDispatchError(dispatchErr)
		refundUserModel(ctx, trGateway, authorization, dispatchFailure, state, req.Metadata)
		writeUserModelBufferedError(conn, routeType, dispatchFailure)
		return
	}

	if routeType == "responses" && len(result.ToolCalls) == 0 {
		normalized, err := adapter.NormalizeResponsesStructuredOutput(result.Text, responseTextConfig(req))
		if err != nil {
			failure := malformedUserModelError(authorization.CustomModel, err)
			refundUserModel(ctx, trGateway, authorization, failure, state, req.Metadata)
			writeUserModelBufferedError(conn, routeType, failure)
			return
		}
		result.Text = normalized
	}

	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(adapter.ResponsesOutputForUsage(result)),
	)
	responseModel := authorizationResponseModel(authorization.Model, authorization)
	var responseBody bytes.Buffer
	var encodeErr error
	switch routeType {
	case "responses":
		encodeErr = adapter.WriteResponsesResponse(
			&responseBody, requestID, responseModel, result.Text, result.ToolCalls,
			inputTokens, outputTokens, result.Usage, userModelNow().Unix(), responseTextConfig(req), req.Response,
		)
	case "messages":
		encodeErr = adapter.WriteMessagesResponse(
			&responseBody, requestID, responseModel, result, inputTokens, outputTokens,
		)
	default:
		encodeErr = adapter.WriteChatCompletionResponse(
			&responseBody, requestID, responseModel, result.Text, adapter.JoinThinking(result.Thinking),
			result.ToolCalls, inputTokens, outputTokens, result.Usage, userModelNow().Unix(), result.FinishReason,
		)
	}
	if encodeErr != nil {
		failure := internalUserModelError(encodeErr)
		refundUserModel(ctx, trGateway, authorization, failure, state, req.Metadata)
		writeUserModelBufferedError(conn, routeType, failure)
		return
	}

	usage := userModelUsage(
		req, authorization, result, requestID, routeType, state,
		inputTokens, outputTokens, usageEstimated, false, result.FinishReason,
	)
	if clientClosed.Load() {
		// Encoding/normalization may take long enough for the watcher to fire
		// after collection. No buffered body has been delivered at this point.
		refundUserModel(ctx, trGateway, authorization, clientClosedUserModelError(context.Canceled), state, req.Metadata)
		return
	}
	settlement, err := settleAndBroadcast(
		ctx, trGateway, authorization, secretCache, usage, req, originalInput,
		adapter.ResponsesOutputForUsage(result),
	)
	if err != nil {
		writeUserModelBufferedSpentError(conn, routeType, internalUserModelError(errors.New("settlement failed")))
		return
	}
	if routeType == "messages" {
		annotated, annotationErr := annotateBatchSettlementOnlyUsage(ctx, responseBody.Bytes(), settlement, authorization)
		if annotationErr != nil {
			writeUserModelBufferedSpentError(conn, routeType, internalUserModelError(annotationErr))
			return
		}
		writeJSONResponse(conn, http.StatusOK, annotated)
		return
	}
	annotated, err := annotateSettledResponseMetadata(
		responseBody.Bytes(), authorization, settlement, selectedRoute,
		[]llm.InvokeOptions{option}, result, req.OpenRouterMetadata,
	)
	if err != nil {
		writeUserModelBufferedSpentError(conn, routeType, internalUserModelError(err))
		return
	}
	writeJSONResponse(conn, http.StatusOK, annotated)
}

func serveUserModelStreaming(
	ctx context.Context,
	conn io.Writer,
	req *types.OpenAIChatRequest,
	rawCallerBody map[string]any,
	anthropicReq *types.AnthropicMessagesRequest,
	routeType string,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	originalInput any,
	selectedRoute *selectedRouteTracker,
	option llm.InvokeOptions,
	requestLogID string,
) {
	requestID := newUserModelRequestID(routeType)
	responseModel := authorizationResponseModel(authorization.Model, authorization)
	if err := writeResponseHead(conn, http.StatusOK, "text/event-stream"); err != nil {
		failure := clientClosedUserModelError(err)
		refundUserModel(ctx, trGateway, authorization, failure, nil, req.Metadata)
		return
	}

	chunked := newChunkedWriter(conn)
	clientWriter := &synchronizedUserModelWriter{w: chunked}
	defer clientWriter.close(chunked)
	statsWriter := newStreamStatsWriter(clientWriter)
	streamWriter := io.Writer(statsWriter)
	var batchWriter io.WriteCloser
	if routeType == "chat.completions" {
		batchWriter = newSSEBatchWriter(statsWriter)
		streamWriter = batchWriter
	}

	state := newUserModelDispatchState()
	state.requestID = requestID
	dispatchCtx, cancel := context.WithCancel(ctx)
	clientClosed := cancelUserModelOnDisconnect(dispatchCtx, cancel, conn)
	pr, pw := io.Pipe()
	var dispatchErr error
	dispatchDone := make(chan struct{})
	go func() {
		dispatchErr = dispatchUserModel(
			dispatchCtx, state, req, rawCallerBody, anthropicReq, authorization.CustomModel, secretCache, pw,
		)
		_ = pw.CloseWithError(dispatchErr)
		close(dispatchDone)
	}()
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		writeUserModelKeepalives(state, dispatchDone, clientWriter, cancel)
	}()

	var result adapter.StreamResult
	var transformErr error
	switch routeType {
	case "responses":
		result, transformErr = adapter.TransformResponsesStream(
			pr, statsWriter, requestID, responseModel, trustedrouter.EstimateInputTokens(req),
			responseTextConfig(req), req.Response,
		)
	case "messages":
		result, transformErr = adapter.RelayAnthropicStream(pr, statsWriter, requestID, responseModel)
	default:
		result, transformErr = adapter.TransformStreamCaptureWithRouterMetadata(
			pr, streamWriter, requestID, responseModel, chatIncludeUsage(req), nil,
		)
	}
	if batchWriter != nil {
		if err := batchWriter.Close(); transformErr == nil {
			transformErr = err
		}
	}
	cancel()
	_ = pr.CloseWithError(transformErr)
	<-dispatchDone
	<-keepaliveDone

	if clientClosed.Load() {
		if clientWriter.bodyBytesWritten() == 0 {
			failure := clientClosedUserModelError(context.Canceled)
			refundUserModel(ctx, trGateway, authorization, failure, state, req.Metadata)
			return
		}
		settlePartialUserModel(
			ctx, trGateway, authorization, secretCache, req, originalInput, clientWriter.deliveredOutput(),
			requestID, routeType, state, true, requestLogID,
		)
		return
	}
	if clientErr := clientWriter.err(); clientErr != nil {
		if clientWriter.bodyBytesWritten() == 0 {
			failure := clientClosedUserModelError(clientErr)
			refundUserModel(ctx, trGateway, authorization, failure, state, req.Metadata)
			return
		}
		settlePartialUserModel(
			ctx, trGateway, authorization, secretCache, req, originalInput, clientWriter.deliveredOutput(),
			requestID, routeType, state, true, requestLogID,
		)
		return
	}
	if transformErr != nil || dispatchErr != nil {
		failure := asUserModelDispatchError(dispatchErr)
		refundUserModel(ctx, trGateway, authorization, failure, state, req.Metadata)
		_ = writeUserModelStreamingError(statsWriter, routeType, requestID, responseModel, failure)
		return
	}

	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(adapter.ResponsesOutputForUsage(result)),
	)
	usage := userModelUsage(
		req, authorization, result, requestID, routeType, state,
		inputTokens, outputTokens, usageEstimated, true, result.FinishReason,
	)
	if _, err := settleAndBroadcast(
		ctx, trGateway, authorization, secretCache, usage, req, originalInput,
		adapter.ResponsesOutputForUsage(result),
	); err != nil {
		settlementRetries.Enqueue(settlementRetryJob{
			trGateway: trGateway, authorization: authorization, usage: usage, requestLogID: requestLogID,
			clientContext: trustedrouter.ClientContextFromContext(ctx),
		})
	}
	clientWriter.complete(chunked)
}

func newUserModelRequestID(routeType string) string {
	switch routeType {
	case "responses":
		return newResponseID()
	case "messages":
		return newMessageID()
	default:
		return newRequestID()
	}
}

func cancelUserModelOnDisconnect(
	ctx context.Context,
	cancel context.CancelFunc,
	conn io.Writer,
) *atomic.Bool {
	closed := &atomic.Bool{}
	disconnected := userModelClientDisconnect(ctx, conn)
	if disconnected == nil {
		return closed
	}
	go func() {
		select {
		case <-disconnected:
			closed.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()
	return closed
}

type synchronizedUserModelWriter struct {
	mu             sync.Mutex
	w              io.Writer
	writeErr       error
	bodyBytes      int64
	dataWritten    bool
	deliveryBuffer []byte
	delivered      strings.Builder
}

func (w *synchronizedUserModelWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	n, err := w.w.Write(p)
	if n > 0 {
		w.bodyBytes += int64(n)
		w.dataWritten = true
		w.captureDeliveredLocked(p[:n])
	}
	if err != nil {
		w.writeErr = err
	}
	return n, err
}

func (w *synchronizedUserModelWriter) writeKeepalive() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	if w.dataWritten {
		// A tick may already be runnable when the transform starts a multi-Write
		// event. Sharing the lock and checking this flag prevents the comment from
		// landing between that event's event: and data: lines.
		return nil
	}
	_, err := io.WriteString(w.w, ": keepalive\n\n")
	if err != nil {
		w.writeErr = err
	}
	return err
}

func (w *synchronizedUserModelWriter) bodyBytesWritten() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bodyBytes
}

func (w *synchronizedUserModelWriter) deliveredOutput() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.delivered.String()
}

func (w *synchronizedUserModelWriter) captureDeliveredLocked(p []byte) {
	w.deliveryBuffer = append(w.deliveryBuffer, p...)
	for {
		event, rest, ok := nextSSEEvent(w.deliveryBuffer)
		if !ok {
			if len(w.deliveryBuffer) > 2*maxUserModelSSEEventBytes {
				// Settlement capture must never become a second unbounded parser. A
				// malformed final event is still counted by bodyBytes for the refund
				// gate, but contributes no speculative output tokens.
				w.deliveryBuffer = nil
			}
			return
		}
		w.captureDeliveredEventLocked(event)
		w.deliveryBuffer = rest
	}
}

func (w *synchronizedUserModelWriter) captureDeliveredEventLocked(event []byte) {
	payload := userModelSSEData(event)
	if payload == nil || bytes.Equal(payload, []byte("[DONE]")) {
		return
	}
	var object map[string]any
	if json.Unmarshal(payload, &object) != nil {
		return
	}
	if choices, ok := object["choices"].([]any); ok && len(choices) > 0 {
		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		w.captureDeliveredDeltaLocked(delta)
		return
	}
	eventType, _ := object["type"].(string)
	switch eventType {
	case "content_block_delta":
		delta, _ := object["delta"].(map[string]any)
		w.captureDeliveredDeltaLocked(delta)
	case "response.output_text.delta", "response.function_call_arguments.delta":
		if delta, ok := object["delta"].(string); ok {
			w.delivered.WriteString(delta)
		}
	}
}

func (w *synchronizedUserModelWriter) captureDeliveredDeltaLocked(delta map[string]any) {
	if delta == nil {
		return
	}
	if content, ok := delta["content"].(string); ok {
		w.delivered.WriteString(content)
	}
	if text, ok := delta["text"].(string); ok && delta["type"] == "text_delta" {
		w.delivered.WriteString(text)
	}
	if partial, ok := delta["partial_json"].(string); ok && delta["type"] == "input_json_delta" {
		w.delivered.WriteString(partial)
	}
	toolCalls, _ := delta["tool_calls"].([]any)
	for _, rawCall := range toolCalls {
		call, _ := rawCall.(map[string]any)
		function, _ := call["function"].(map[string]any)
		if arguments, ok := function["arguments"].(string); ok {
			w.delivered.WriteString(arguments)
		}
	}
}

func (w *synchronizedUserModelWriter) err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeErr
}

func (w *synchronizedUserModelWriter) close(chunked *chunkedWriter) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr == nil {
		w.writeErr = chunked.Close()
	}
}

func (w *synchronizedUserModelWriter) complete(chunked *chunkedWriter) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr == nil {
		w.writeErr = chunked.Complete()
	}
}

func writeUserModelKeepalives(
	state *userModelDispatchState,
	dispatchDone <-chan struct{},
	w *synchronizedUserModelWriter,
	cancel context.CancelFunc,
) {
	interval := userModelKeepaliveInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-state.firstByte:
			return
		case <-dispatchDone:
			return
		case <-ticker.C:
			if err := w.writeKeepalive(); err != nil {
				cancel()
				return
			}
		}
	}
}

func settlePartialUserModel(
	ctx context.Context,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	req *types.OpenAIChatRequest,
	originalInput any,
	deliveredOutput string,
	requestID string,
	routeType string,
	state *userModelDispatchState,
	streamed bool,
	requestLogID string,
) {
	inputTokens := trustedrouter.EstimateInputTokens(req)
	outputTokens := trustedrouter.EstimateOutputTokens(deliveredOutput)
	result := adapter.StreamResult{Text: deliveredOutput}
	usage := userModelUsage(
		req, authorization, result, requestID, routeType, state,
		inputTokens, outputTokens, true, streamed, "client_closed",
	)
	if _, err := settleAndBroadcast(
		ctx, trGateway, authorization, secretCache, usage, req, originalInput,
		deliveredOutput,
	); err != nil {
		settlementRetries.Enqueue(settlementRetryJob{
			trGateway: trGateway, authorization: authorization, usage: usage, requestLogID: requestLogID,
			clientContext: trustedrouter.ClientContextFromContext(ctx),
		})
	}
}

func userModelUsage(
	req *types.OpenAIChatRequest,
	authorization *trustedrouter.Authorization,
	result adapter.StreamResult,
	requestID string,
	routeType string,
	state *userModelDispatchState,
	inputTokens int,
	outputTokens int,
	usageEstimated bool,
	streamed bool,
	finishReason string,
) trustedrouter.Usage {
	usage := trustedrouter.Usage{
		RequestID: requestID, InputTokens: inputTokens, OutputTokens: outputTokens,
		ElapsedSeconds: state.elapsedSeconds(), FirstTokenSeconds: state.firstTokenSeconds(),
		UsageEstimated: usageEstimated, FinishReason: finishReason, Streamed: streamed,
		RouteType: routeType, SelectedModel: authorization.Model, SelectedEndpoint: authorization.EndpointID,
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
		ServiceTier: requestedServiceTierForSettlement(req),
	}
	applyUsageAttribution(&usage, req)
	applyCacheUsage(&usage, result)
	return usage
}

func refundUserModel(
	ctx context.Context,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	failure *userModelDispatchError,
	state *userModelDispatchState,
	metadata map[string]any,
) {
	if trGateway == nil || !trGateway.Enabled() || authorization == nil || failure == nil {
		return
	}
	elapsed := 0.001
	if state != nil {
		elapsed = state.elapsedSeconds()
	}
	_, _ = trGateway.RefundDetailed(
		ctx, authorization, failure.refundStatus, failure.refundType, elapsed, metadata,
	)
}

func asUserModelDispatchError(err error) *userModelDispatchError {
	var dispatchErr *userModelDispatchError
	if errors.As(err, &dispatchErr) {
		return dispatchErr
	}
	return internalUserModelError(err)
}

func writeUserModelBufferedError(w io.Writer, routeType string, failure *userModelDispatchError) {
	writeUserModelBufferedErrorWithHeaders(w, routeType, failure, nil)
}

func writeUserModelBufferedSpentError(w io.Writer, routeType string, failure *userModelDispatchError) {
	// A complete owner generation has already consumed the owner's compute.
	// Tell SDKs not to fail over and generate a second billable answer when
	// settlement or post-settlement response annotation fails.
	writeUserModelBufferedErrorWithHeaders(
		w, routeType, failure, map[string]string{shouldRetryHeader: "false"},
	)
}

func writeUserModelBufferedErrorWithHeaders(
	w io.Writer,
	routeType string,
	failure *userModelDispatchError,
	headers map[string]string,
) {
	if failure == nil || failure.callerStatus == 499 {
		return
	}
	var body []byte
	if routeType == "messages" {
		body, _ = json.Marshal(map[string]any{
			"type":  "error",
			"error": map[string]any{"type": failure.refundType, "message": failure.message},
		})
	} else {
		body, _ = json.Marshal(map[string]any{
			"error": map[string]any{
				"message": failure.message,
				"type":    failure.refundType,
				"param":   nil,
				"code":    failure.refundType,
				"source":  "router",
			},
		})
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: %s\r\n", failure.callerStatus, statusText(failure.callerStatus), len(body), responseConnection(w))
	for name, value := range headers {
		if value != "" {
			fmt.Fprintf(w, "%s: %s\r\n", name, value)
		}
	}
	_, _ = io.WriteString(w, "\r\n")
	_, _ = w.Write(body)
}

func writeUserModelStreamingError(
	w io.Writer,
	routeType string,
	requestID string,
	model string,
	failure *userModelDispatchError,
) error {
	errorBody := map[string]any{
		"message": failure.message, "type": failure.refundType,
		"source": "provider", "status": failure.callerStatus,
	}
	if routeType == "responses" {
		return writeUserModelEvent(w, "response.failed", map[string]any{
			"type": "response.failed",
			"response": map[string]any{
				"id": requestID, "object": "response", "created_at": userModelNow().Unix(),
				"model": model, "status": "failed", "error": errorBody,
			},
		})
	}
	if routeType == "messages" {
		return writeUserModelEvent(w, "error", map[string]any{"type": "error", "error": errorBody})
	}
	body, err := json.Marshal(map[string]any{"error": errorBody})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", body)
	return err
}

func writeUserModelPlaneError(w io.Writer, routeType string) {
	failure := &userModelDispatchError{
		callerStatus: http.StatusServiceUnavailable,
		refundStatus: http.StatusServiceUnavailable,
		refundType:   "user_model_unavailable_on_plane",
		message:      "User-provided models are not served from this region yet",
	}
	writeUserModelBufferedError(w, routeType, failure)
}
