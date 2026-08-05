package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenAIFileBatchProviderUsesStreamingSafeHTTPTimeouts(t *testing.T) {
	t.Parallel()

	provider := NewOpenAIFileBatchProvider(
		"openai", "https://provider.invalid/v1", "secret", "/v1/chat/completions",
	)
	if provider.httpc.Timeout != 0 {
		t.Fatalf("whole-response timeout = %s, want zero for large result streams", provider.httpc.Timeout)
	}
	transport, ok := provider.httpc.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout != nativeJSONTimeout {
		t.Fatalf("transport = %#v", provider.httpc.Transport)
	}
	if nativeResultTimeout < 4*time.Hour {
		t.Fatalf("result reconciliation timeout = %s, want at least 4h", nativeResultTimeout)
	}
}

func TestOpenAIBatchJSONLUsesEndpointSpecificBodyShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		endpoint   string
		body       string
		wantStream bool
	}{
		{
			name: "chat disables streaming", endpoint: "/v1/chat/completions",
			body:       `{"messages":[{"role":"user","content":"PONG"}],"stream":true}`,
			wantStream: true,
		},
		{
			name: "embeddings omit chat-only stream field", endpoint: "/v1/embeddings",
			body: `{"input":"PONG","stream":true}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := openAIBatchJSONL("openai", "stable-token", test.endpoint, "upstream-model", []NativeProviderRequest{{
				Index: 0, Body: json.RawMessage(test.body),
			}})
			if err != nil {
				t.Fatalf("openAIBatchJSONL: %v", err)
			}
			var line struct {
				Body map[string]any `json:"body"`
			}
			if json.Unmarshal(bytes.TrimSpace(encoded), &line) != nil {
				t.Fatalf("jsonl = %s", encoded)
			}
			stream, present := line.Body["stream"]
			if test.wantStream {
				if !present || stream != false {
					t.Fatalf("chat stream = %#v, present=%t", stream, present)
				}
			} else if present {
				t.Fatalf("embedding body leaked stream=%#v", stream)
			}
		})
	}
}

func TestNativeProviderBodyNormalizesRouterOnlyChatFields(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		provider string
		wantKey  string
	}{
		{provider: "openai", wantKey: "max_completion_tokens"},
		{provider: "parasail", wantKey: "max_tokens"},
	} {
		t.Run(test.provider, func(t *testing.T) {
			t.Parallel()
			body, err := nativeProviderBody(
				test.provider,
				"/v1/chat/completions",
				[]byte(`{"model":"requested","messages":[],"max_tokens":123,"max_completion_tokens":456,"max_output_tokens":789,"reasoning":{"effort":"high"}}`),
				"upstream-model",
			)
			if err != nil {
				t.Fatalf("nativeProviderBody: %v", err)
			}
			if body[test.wantKey] != json.Number("123") || body["reasoning_effort"] != "high" {
				t.Fatalf("body = %#v", body)
			}
			for _, key := range []string{"reasoning", "max_output_tokens"} {
				if _, present := body[key]; present {
					t.Fatalf("body retained %q: %#v", key, body)
				}
			}
			otherKey := "max_tokens"
			if test.wantKey == otherKey {
				otherKey = "max_completion_tokens"
			}
			if _, present := body[otherKey]; present {
				t.Fatalf("body retained competing token limit %q: %#v", otherKey, body)
			}
		})
	}
}

func TestOpenAIFileBatchProviderSubmitPollAndCleanup(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	deleted := map[string]bool{}
	fileListCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer provider-secret" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/files":
			fileListCalls++
			if request.URL.Query().Get("purpose") != "batch" || request.URL.Query().Get("limit") != "100" {
				t.Fatalf("file recovery query = %s", request.URL.String())
			}
			return jsonResponse(200, `{"data":[],"has_more":false}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1/files":
			if _, ok := request.Body.(*io.PipeReader); !ok {
				t.Fatalf("upload body type = %T; input must stream through a pipe", request.Body)
			}
			mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
			if err != nil || mediaType != "multipart/form-data" {
				t.Fatalf("content type = %q err=%v", mediaType, err)
			}
			reader := multipart.NewReader(request.Body, params["boundary"])
			fields := map[string]string{}
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("multipart: %v", err)
				}
				value, _ := io.ReadAll(part)
				fields[part.FormName()] = string(value)
			}
			if fields["purpose"] != "batch" ||
				fields["expires_after[anchor]"] != "created_at" ||
				fields["expires_after[seconds]"] != strconv.Itoa(nativeInputExpirySeconds) ||
				!strings.Contains(fields["file"], `"custom_id":"stable-token_item_1"`) {
				t.Fatalf("multipart fields = %#v", fields)
			}
			if strings.Contains(fields["file"], `"provider"`) || strings.Contains(fields["file"], `"models"`) ||
				strings.Contains(fields["file"], `"service_tier"`) || strings.Contains(fields["file"], `"customer-user-marker"`) {
				t.Fatalf("router-only fields leaked upstream: %s", fields["file"])
			}
			return jsonResponse(200, `{"id":"file-input"}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1/batches":
			if request.Header.Get("Idempotency-Key") != "stable-token:create" {
				t.Fatalf("idempotency = %q", request.Header.Get("Idempotency-Key"))
			}
			body, _ := io.ReadAll(request.Body)
			var payload map[string]any
			if json.Unmarshal(body, &payload) != nil || payload["input_file_id"] != "file-input" ||
				payload["endpoint"] != "/v1/chat/completions" {
				t.Fatalf("create payload = %s", body)
			}
			metadata := payload["metadata"].(map[string]any)
			if metadata["trustedrouter_batch_token"] != "stable-token" {
				t.Fatalf("metadata = %#v", metadata)
			}
			expiry := payload["output_expires_after"].(map[string]any)
			if expiry["anchor"] != "created_at" || expiry["seconds"] != float64(nativeOutputExpirySeconds) {
				t.Fatalf("output expiry = %#v", expiry)
			}
			return jsonResponse(200, `{"id":"batch-provider","input_file_id":"file-input","status":"validating"}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1/batches/batch-provider":
			return jsonResponse(200, `{"id":"batch-provider","status":"completed","input_file_id":"file-input","output_file_id":"file-output","error_file_id":"file-error"}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1/files/file-output/content":
			return jsonResponse(200, strings.Join([]string{
				`{"custom_id":"stable-token_item_1","response":{"status_code":200,"request_id":"req-1","body":{"id":"chat-1","usage":{"prompt_tokens":4,"completion_tokens":2}}}}`,
				`{"custom_id":"stable-token_item_0","response":{"status_code":200,"request_id":"req-0","body":{"id":"chat-0","usage":{"prompt_tokens":3,"completion_tokens":1}}}}`,
			}, "\n")), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1/files/file-error/content":
			return jsonResponse(200, ""), nil
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/files/"):
			mu.Lock()
			deleted[strings.TrimPrefix(request.URL.Path, "/v1/files/")] = true
			mu.Unlock()
			return jsonResponse(200, `{}`), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "provider-secret", client,
		"/v1/chat/completions",
	)
	job, err := provider.Submit(t.Context(), "stable-token", "/v1/chat/completions", "gpt-upstream", []NativeProviderRequest{
		{Index: 0, Body: json.RawMessage(`{"model":"public/model","messages":[{"role":"user","content":"first"}],"provider":{"only":["OpenAI"]},"service_tier":"priority","user":"customer-user-marker"}`)},
		{Index: 1, Body: json.RawMessage(`{"model":"public/model","messages":[{"role":"user","content":"second"}],"models":["fallback"]}`)},
	}, false)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if job.ID != "batch-provider" || job.InputFileID != "file-input" {
		t.Fatalf("job = %#v", job)
	}
	if fileListCalls != 0 {
		t.Fatalf("first submission scanned existing files %d times", fileListCalls)
	}
	poll, err := provider.Poll(t.Context(), job)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if poll.Status != NativeStatusComplete {
		t.Fatalf("poll = %#v", poll)
	}
	var results []NativeProviderResult
	if err := provider.Results(t.Context(), poll.Job, func(result NativeProviderResult) error {
		results = append(results, NativeProviderResult{
			Index:      result.Index,
			StatusCode: result.StatusCode,
			RequestID:  result.RequestID,
			Body:       cloneRaw(result.Body),
			Error:      cloneRaw(result.Error),
		})
		return nil
	}); err != nil {
		t.Fatalf("Results: %v", err)
	}
	if len(results) != 2 || results[0].Index != 1 || results[1].Index != 0 {
		t.Fatalf("results = %#v", results)
	}
	if err := provider.Cleanup(t.Context(), poll.Job); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, fileID := range []string{"file-input", "file-output", "file-error"} {
		if !deleted[fileID] {
			t.Fatalf("file %q was not deleted", fileID)
		}
	}
}

func TestOpenAIFileBatchProviderReusesRecoveredInputFile(t *testing.T) {
	t.Parallel()

	uploads := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/files":
			return jsonResponse(200, `{"data":[{"id":"existing-input","filename":"stable-token.jsonl"}],"has_more":false}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1/files":
			uploads++
			return jsonResponse(200, `{"id":"duplicate-input"}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v1/batches":
			body, _ := io.ReadAll(request.Body)
			if !bytes.Contains(body, []byte(`"input_file_id":"existing-input"`)) {
				t.Fatalf("batch did not use recovered input: %s", body)
			}
			return jsonResponse(200, `{"id":"batch-provider","input_file_id":"existing-input"}`), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "provider-secret", client,
		"/v1/chat/completions",
	)
	job, err := provider.Submit(t.Context(), "stable-token", "/v1/chat/completions", "gpt-upstream", []NativeProviderRequest{{
		Index: 0,
		// Recovery must not rebuild or inspect JSONL that was already uploaded.
		Body: json.RawMessage(`{`),
	}}, true)
	if err != nil || job.InputFileID != "existing-input" || uploads != 0 {
		t.Fatalf("Submit = %#v, %v; uploads=%d", job, err, uploads)
	}
}

func TestOpenAIFileBatchProviderRecoversSubmissionByOpaqueToken(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/batches" || request.URL.Query().Get("limit") != "100" {
			t.Fatalf("request = %s", request.URL.String())
		}
		return jsonResponse(200, `{"data":[{"id":"other","metadata":{"trustedrouter_batch_token":"other"}},{"id":"found","input_file_id":"input","metadata":{"trustedrouter_batch_token":"stable-token"}}],"has_more":false}`), nil
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"parasail", "https://provider.invalid/v1", "secret", client, "/v1/chat/completions",
	)
	job, err := provider.Recover(t.Context(), "stable-token")
	if err != nil || job.ID != "found" || job.InputFileID != "input" {
		t.Fatalf("Recover = %#v, %v", job, err)
	}
}

func TestOpenAIFileBatchProviderRejectsRecoveredSubmissionWithoutID(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(
			http.StatusOK,
			`{"data":[{"id":"","metadata":{"trustedrouter_batch_token":"stable-token"}}],"has_more":false}`,
		), nil
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "secret", client, "/v1/chat/completions",
	)
	if job, err := provider.Recover(t.Context(), "stable-token"); err == nil || job.ID != "" {
		t.Fatalf("Recover = %#v, %v", job, err)
	}
}

func TestOpenAIFileBatchProviderRecoveryPaginatesBeyondOneThousandJobs(t *testing.T) {
	t.Parallel()

	page := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		page++
		data := make([]map[string]any, 100)
		for index := range data {
			data[index] = map[string]any{
				"id":       fmt.Sprintf("batch-%02d-%03d", page, index),
				"metadata": map[string]string{"trustedrouter_batch_token": "other"},
			}
		}
		if page == 12 {
			data[17]["id"] = "batch-found"
			data[17]["metadata"] = map[string]string{"trustedrouter_batch_token": "stable-token"}
		}
		encoded, _ := json.Marshal(map[string]any{"data": data, "has_more": true})
		return jsonResponse(http.StatusOK, string(encoded)), nil
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "secret", client, "/v1/chat/completions",
	)
	job, err := provider.Recover(t.Context(), "stable-token")
	if err != nil || job.ID != "batch-found" || page != 12 {
		t.Fatalf("Recover = %#v, %v; pages=%d", job, err, page)
	}
}

func TestOpenAIFileBatchProviderInputRecoveryPaginatesBeyondOneThousandFiles(t *testing.T) {
	t.Parallel()

	page := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		page++
		data := make([]map[string]any, 100)
		for index := range data {
			data[index] = map[string]any{
				"id":       fmt.Sprintf("file-%02d-%03d", page, index),
				"filename": "other.jsonl",
			}
		}
		if page == 12 {
			data[23]["id"] = "file-found"
			data[23]["filename"] = "stable-token.jsonl"
		}
		encoded, _ := json.Marshal(map[string]any{"data": data, "has_more": true})
		return jsonResponse(http.StatusOK, string(encoded)), nil
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "secret", client, "/v1/chat/completions",
	)
	fileID, err := provider.recoverInputFile(t.Context(), "stable-token")
	if err != nil || fileID != "file-found" || page != 12 {
		t.Fatalf("recoverInputFile = %q, %v; pages=%d", fileID, err, page)
	}
}

func TestOpenAIFileBatchProviderErrorsNeverContainProviderBodyOrKey(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.Path == "/v1/files" {
			return jsonResponse(200, `{"data":[],"has_more":false}`), nil
		}
		return jsonResponse(400, `{"error":{"message":"private-prompt-marker provider-secret"}}`), nil
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "provider-secret", client, "/v1/chat/completions",
	)
	_, err := provider.Submit(context.Background(), "token", "/v1/chat/completions", "model", []NativeProviderRequest{{
		Index: 0,
		Body:  json.RawMessage(`{"messages":[{"role":"user","content":"private-prompt-marker"}]}`),
	}}, false)
	if err == nil {
		t.Fatal("Submit unexpectedly succeeded")
	}
	if bytes.Contains([]byte(err.Error()), []byte("private-prompt-marker")) ||
		bytes.Contains([]byte(err.Error()), []byte("provider-secret")) {
		t.Fatalf("sensitive provider body leaked in error: %v", err)
	}
}

func TestOpenAIFileBatchProviderCancelsWithOperationSpecificIdempotencyToken(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/batches/job-1/cancel" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Idempotency-Key") != "stable-token:cancel" {
			t.Fatalf("idempotency = %q", request.Header.Get("Idempotency-Key"))
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "provider-secret", client, "/v1/chat/completions",
	)
	if err := provider.Cancel(t.Context(), NativeProviderJob{ID: "job-1", Token: "stable-token"}); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
}

func TestOpenAIFileBatchProviderPrefersOutputOverDuplicateErrorFileEntry(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/files/output/content":
			return jsonResponse(200, `{"custom_id":"stable-token_item_0","response":{"status_code":200,"body":{"id":"ok"}}}`), nil
		case "/v1/files/error/content":
			return jsonResponse(200, `{"custom_id":"stable-token_item_0","error":{"message":"duplicate"}}`), nil
		default:
			t.Fatalf("unexpected request: %s", request.URL.Path)
			return nil, nil
		}
	})}
	provider := NewOpenAIFileBatchProviderForTest(
		"openai", "https://provider.invalid/v1", "provider-secret", client,
		"/v1/chat/completions",
	)
	consumed := 0
	err := provider.Results(t.Context(), NativeProviderJob{
		OutputFileID: "output",
		ErrorFileID:  "error",
		Token:        "stable-token",
	}, func(result NativeProviderResult) error {
		consumed++
		if result.Index != 0 || result.StatusCode != http.StatusOK {
			t.Fatalf("result = %#v", result)
		}
		return nil
	})
	if err != nil || consumed != 1 {
		t.Fatalf("Results error = %v, consumed = %d", err, consumed)
	}
}

func TestOpenAIBatchResultParserClassifiesImmutableMalformedLines(t *testing.T) {
	t.Parallel()

	for name, payload := range map[string]string{
		"invalid json":      `{`,
		"unknown custom id": `{"custom_id":"customer-controlled"}`,
		"other batch token": `{"custom_id":"other-token_item_0"}`,
	} {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := parseOpenAIBatchResultStream(
				strings.NewReader(payload), false, "stable-token", func(NativeProviderResult) error { return nil },
			)
			if !errors.Is(err, ErrNativeInvalidResult) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
