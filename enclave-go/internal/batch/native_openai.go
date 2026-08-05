package batch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	nativeInputExpirySeconds  = 26 * 60 * 60
	nativeOutputExpirySeconds = 6 * 60 * 60
	nativeJSONTimeout         = 2 * time.Minute
	nativeUploadTimeout       = 10 * time.Minute
	// Result reads are intentionally much longer than JSON control calls. The
	// provider stream is backpressured by per-item durable settlement, so a
	// valid 50,000-item file can take well over 30 minutes to reconcile.
	nativeResultTimeout     = 4 * time.Hour
	nativeRecoveryPageLimit = 1_000
)

type nativeProviderHTTPError struct {
	provider  string
	operation string
	status    int
}

func (e *nativeProviderHTTPError) Error() string {
	return fmt.Sprintf("native batch provider %s %s status %d", e.provider, e.operation, e.status)
}

type nativeProviderTransportError struct {
	provider  string
	operation string
}

func (e *nativeProviderTransportError) Error() string {
	return fmt.Sprintf("native batch provider %s %s transport failed", e.provider, e.operation)
}

// OpenAIFileBatchProvider implements the OpenAI Files + Batches contract used
// by OpenAI and Parasail. The base URL is provider-specific; prompts and
// outputs stay inside the enclave and are never included in adapter errors.
type OpenAIFileBatchProvider struct {
	name      string
	baseURL   string
	apiKey    string
	endpoints map[string]struct{}
	httpc     *http.Client
}

func NewOpenAIFileBatchProvider(
	name string,
	baseURL string,
	apiKey string,
	endpoints ...string,
) *OpenAIFileBatchProvider {
	supported := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			supported[endpoint] = struct{}{}
		}
	}
	return &OpenAIFileBatchProvider{
		name:      strings.TrimSpace(name),
		baseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:    strings.TrimSpace(apiKey),
		endpoints: supported,
		httpc: &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: nativeJSONTimeout,
			ExpectContinueTimeout: time.Second,
		}},
	}
}

func NewOpenAIFileBatchProviderForTest(
	name string,
	baseURL string,
	apiKey string,
	httpc *http.Client,
	endpoints ...string,
) *OpenAIFileBatchProvider {
	provider := NewOpenAIFileBatchProvider(name, baseURL, apiKey, endpoints...)
	if httpc != nil {
		provider.httpc = httpc
	}
	return provider
}

func (p *OpenAIFileBatchProvider) Name() string { return p.name }

func (p *OpenAIFileBatchProvider) Supports(endpoint string) bool {
	if p == nil || p.name == "" || p.baseURL == "" || p.apiKey == "" {
		return false
	}
	_, ok := p.endpoints[endpoint]
	return ok
}

func (p *OpenAIFileBatchProvider) Submit(
	ctx context.Context,
	token string,
	endpoint string,
	upstreamModel string,
	requests []NativeProviderRequest,
	recoverInput bool,
) (NativeProviderJob, error) {
	job := NativeProviderJob{Provider: p.name, Token: token}
	if !p.Supports(endpoint) {
		return job, fmt.Errorf("native batch provider %s does not support endpoint", p.name)
	}
	var fileID string
	var err error
	if recoverInput {
		fileID, err = p.recoverInputFile(ctx, token)
		if err != nil && !errors.Is(err, ErrNativeNotFound) {
			return job, err
		}
	}
	if strings.TrimSpace(fileID) == "" {
		fileID, err = p.uploadInput(ctx, token, endpoint, upstreamModel, requests)
	}
	if err != nil {
		return job, err
	}
	job.InputFileID = fileID

	payload := map[string]any{
		"input_file_id":     fileID,
		"endpoint":          endpoint,
		"completion_window": "24h",
		"metadata":          map[string]string{"trustedrouter_batch_token": token},
		"output_expires_after": map[string]any{
			"anchor":  "created_at",
			"seconds": nativeOutputExpirySeconds,
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return job, err
	}
	var created openAIBatchObject
	if err := p.doJSON(ctx, http.MethodPost, "/batches", encoded, token+":create", &created); err != nil {
		return job, err
	}
	if strings.TrimSpace(created.ID) == "" {
		return job, fmt.Errorf("native batch provider %s returned no job id", p.name)
	}
	job.ID = created.ID
	job.OutputFileID = created.OutputFileID
	job.ErrorFileID = created.ErrorFileID
	return job, nil
}

func (p *OpenAIFileBatchProvider) Recover(
	ctx context.Context,
	token string,
) (NativeProviderJob, error) {
	query := "/batches?limit=100"
	previousAfter := ""
	for page := 0; page < nativeRecoveryPageLimit; page++ {
		var listed struct {
			Data    []openAIBatchObject `json:"data"`
			HasMore bool                `json:"has_more"`
		}
		if err := p.doJSON(ctx, http.MethodGet, query, nil, "", &listed); err != nil {
			return NativeProviderJob{}, err
		}
		for _, candidate := range listed.Data {
			if candidate.Metadata["trustedrouter_batch_token"] == token {
				if strings.TrimSpace(candidate.ID) == "" {
					return NativeProviderJob{}, fmt.Errorf(
						"native batch provider %s returned no recovered job id", p.name,
					)
				}
				return NativeProviderJob{
					Provider:     p.name,
					ID:           candidate.ID,
					InputFileID:  candidate.InputFileID,
					OutputFileID: candidate.OutputFileID,
					ErrorFileID:  candidate.ErrorFileID,
					Token:        token,
				}, nil
			}
		}
		if !listed.HasMore || len(listed.Data) == 0 {
			return NativeProviderJob{}, ErrNativeNotFound
		}
		after := listed.Data[len(listed.Data)-1].ID
		if strings.TrimSpace(after) == "" || after == previousAfter {
			return NativeProviderJob{}, fmt.Errorf("native batch provider %s returned an invalid recovery cursor", p.name)
		}
		previousAfter = after
		query = "/batches?limit=100&after=" + url.QueryEscape(after)
	}
	return NativeProviderJob{}, fmt.Errorf("native batch provider %s recovery page limit exceeded", p.name)
}

func (p *OpenAIFileBatchProvider) Poll(
	ctx context.Context,
	job NativeProviderJob,
) (NativeProviderPoll, error) {
	var current openAIBatchObject
	if err := p.doJSON(ctx, http.MethodGet, "/batches/"+url.PathEscape(job.ID), nil, "", &current); err != nil {
		return NativeProviderPoll{}, err
	}
	job.InputFileID = firstNonEmpty(current.InputFileID, job.InputFileID)
	job.OutputFileID = firstNonEmpty(current.OutputFileID, job.OutputFileID)
	job.ErrorFileID = firstNonEmpty(current.ErrorFileID, job.ErrorFileID)
	status := strings.ToLower(strings.TrimSpace(current.Status))
	switch status {
	case "completed":
		return NativeProviderPoll{Status: NativeStatusComplete, Job: job}, nil
	case "failed", "expired", "cancelled":
		return NativeProviderPoll{Status: NativeStatusFailed, Job: job, Error: status}, nil
	default:
		return NativeProviderPoll{Status: NativeStatusPending, Job: job}, nil
	}
}

func (p *OpenAIFileBatchProvider) Results(
	ctx context.Context,
	job NativeProviderJob,
	consume func(NativeProviderResult) error,
) error {
	seen := make(map[int]bool)
	for _, file := range []struct {
		id      string
		isError bool
	}{
		{id: job.OutputFileID},
		{id: job.ErrorFileID, isError: true},
	} {
		if file.id == "" {
			continue
		}
		if err := p.streamResultFile(ctx, file.id, file.isError, job.Token, func(result NativeProviderResult) error {
			if previousWasError, duplicate := seen[result.Index]; duplicate {
				// Providers occasionally repeat a successful output item in the
				// error file. The output file is authoritative and was consumed
				// first, so ignore only that cross-file duplicate. Duplicates
				// within either immutable file remain a structural error.
				if file.isError && !previousWasError {
					return nil
				}
				return fmt.Errorf(
					"%w: provider %s returned duplicate item %d",
					ErrNativeInvalidResult, p.name, result.Index,
				)
			}
			seen[result.Index] = file.isError
			return consume(result)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (p *OpenAIFileBatchProvider) Cancel(ctx context.Context, job NativeProviderJob) error {
	if strings.TrimSpace(job.ID) == "" {
		return nil
	}
	err := p.doJSON(
		ctx,
		http.MethodPost,
		"/batches/"+url.PathEscape(job.ID)+"/cancel",
		[]byte(`{}`),
		job.Token+":cancel",
		nil,
	)
	var statusErr *nativeProviderHTTPError
	if errors.As(err, &statusErr) && (statusErr.status == http.StatusNotFound || statusErr.status == http.StatusConflict) {
		return nil
	}
	return err
}

func (p *OpenAIFileBatchProvider) Cleanup(ctx context.Context, job NativeProviderJob) error {
	var cleanupErr error
	for _, fileID := range []string{job.InputFileID, job.OutputFileID, job.ErrorFileID} {
		if strings.TrimSpace(fileID) == "" {
			continue
		}
		if err := p.doJSON(ctx, http.MethodDelete, "/files/"+url.PathEscape(fileID), nil, "", nil); err != nil {
			var statusErr *nativeProviderHTTPError
			if errors.As(err, &statusErr) && statusErr.status == http.StatusNotFound {
				continue
			}
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return cleanupErr
}

type openAIBatchObject struct {
	ID           string            `json:"id"`
	Status       string            `json:"status"`
	InputFileID  string            `json:"input_file_id"`
	OutputFileID string            `json:"output_file_id"`
	ErrorFileID  string            `json:"error_file_id"`
	Metadata     map[string]string `json:"metadata"`
}

type openAIFileObject struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
}

func (p *OpenAIFileBatchProvider) recoverInputFile(ctx context.Context, token string) (string, error) {
	filename := token + ".jsonl"
	query := "/files?purpose=batch&limit=100&order=desc"
	previousAfter := ""
	for page := 0; page < nativeRecoveryPageLimit; page++ {
		var listed struct {
			Data    []openAIFileObject `json:"data"`
			HasMore bool               `json:"has_more"`
		}
		if err := p.doJSON(ctx, http.MethodGet, query, nil, "", &listed); err != nil {
			return "", err
		}
		for _, candidate := range listed.Data {
			if candidate.Filename == filename && strings.TrimSpace(candidate.ID) != "" {
				return candidate.ID, nil
			}
		}
		if !listed.HasMore || len(listed.Data) == 0 {
			return "", ErrNativeNotFound
		}
		after := listed.Data[len(listed.Data)-1].ID
		if strings.TrimSpace(after) == "" || after == previousAfter {
			return "", fmt.Errorf("native batch provider %s returned an invalid file recovery cursor", p.name)
		}
		previousAfter = after
		query = "/files?purpose=batch&limit=100&order=desc&after=" + url.QueryEscape(after)
	}
	return "", fmt.Errorf("native batch provider %s file recovery page limit exceeded", p.name)
}

func (p *OpenAIFileBatchProvider) uploadInput(
	ctx context.Context,
	token string,
	endpoint string,
	upstreamModel string,
	requests []NativeProviderRequest,
) (string, error) {
	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	contentType := multipartWriter.FormDataContentType()
	writeDone := make(chan error, 1)
	go func() {
		err := writeOpenAIBatchMultipart(
			multipartWriter, p.name, token, endpoint, upstreamModel, requests,
		)
		if err == nil {
			err = multipartWriter.Close()
		}
		if err != nil {
			_ = writer.CloseWithError(err)
		} else {
			_ = writer.Close()
		}
		writeDone <- err
	}()
	defer reader.Close()
	requestCtx, cancel := context.WithTimeout(ctx, nativeUploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, p.baseURL+"/files", reader)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-writeDone
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", contentType)
	resp, err := p.httpc.Do(req)
	// A provider may reject the upload before consuming the whole request.
	// Closing the read side unblocks the streaming encoder in that case.
	_ = reader.Close()
	if err != nil {
		if writeErr := <-writeDone; writeErr != nil {
			return "", writeErr
		}
		return "", &nativeProviderTransportError{provider: p.name, operation: "upload"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		<-writeDone
		drainResponse(resp.Body)
		return "", &nativeProviderHTTPError{provider: p.name, operation: "upload", status: resp.StatusCode}
	}
	if writeErr := <-writeDone; writeErr != nil {
		return "", writeErr
	}
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&decoded); err != nil {
		return "", fmt.Errorf("native batch provider %s upload response invalid", p.name)
	}
	if strings.TrimSpace(decoded.ID) == "" {
		return "", fmt.Errorf("native batch provider %s upload returned no file id", p.name)
	}
	return decoded.ID, nil
}

func writeOpenAIBatchMultipart(
	writer *multipart.Writer,
	provider string,
	token string,
	endpoint string,
	upstreamModel string,
	requests []NativeProviderRequest,
) error {
	if err := writer.WriteField("purpose", "batch"); err != nil {
		return err
	}
	if err := writer.WriteField("expires_after[anchor]", "created_at"); err != nil {
		return err
	}
	if err := writer.WriteField(
		"expires_after[seconds]", strconv.Itoa(nativeInputExpirySeconds),
	); err != nil {
		return err
	}
	fileWriter, err := writer.CreateFormFile("file", token+".jsonl")
	if err != nil {
		return err
	}
	return writeOpenAIBatchJSONL(
		fileWriter, provider, token, endpoint, upstreamModel, requests,
	)
}

func (p *OpenAIFileBatchProvider) doJSON(
	ctx context.Context,
	method string,
	requestPath string,
	body []byte,
	idempotencyKey string,
	out any,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, nativeJSONTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, p.baseURL+requestPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := p.httpc.Do(req)
	if err != nil {
		return &nativeProviderTransportError{provider: p.name, operation: requestPath}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainResponse(resp.Body)
		return &nativeProviderHTTPError{provider: p.name, operation: requestPath, status: resp.StatusCode}
	}
	if out == nil {
		drainResponse(resp.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(out); err != nil {
		return fmt.Errorf("native batch provider %s returned invalid JSON", p.name)
	}
	return nil
}

func (p *OpenAIFileBatchProvider) streamResultFile(
	ctx context.Context,
	fileID string,
	isErrorFile bool,
	token string,
	consume func(NativeProviderResult) error,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, nativeResultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		p.baseURL+"/files/"+url.PathEscape(fileID)+"/content",
		nil,
	)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	resp, err := p.httpc.Do(req)
	if err != nil {
		return &nativeProviderTransportError{provider: p.name, operation: "result"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainResponse(resp.Body)
		return &nativeProviderHTTPError{provider: p.name, operation: "result", status: resp.StatusCode}
	}
	return parseOpenAIBatchResultStream(resp.Body, isErrorFile, token, consume)
}

func openAIBatchJSONL(
	provider string,
	token string,
	endpoint string,
	upstreamModel string,
	requests []NativeProviderRequest,
) ([]byte, error) {
	var out bytes.Buffer
	if err := writeOpenAIBatchJSONL(
		&out, provider, token, endpoint, upstreamModel, requests,
	); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeOpenAIBatchJSONL(
	writer io.Writer,
	provider string,
	token string,
	endpoint string,
	upstreamModel string,
	requests []NativeProviderRequest,
) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, request := range requests {
		body, err := nativeProviderBody(provider, endpoint, request.Body, upstreamModel)
		if err != nil {
			return err
		}
		line := map[string]any{
			"custom_id": nativeResultID(token, request.Index),
			"method":    http.MethodPost,
			"url":       endpoint,
			"body":      body,
		}
		if err := encoder.Encode(line); err != nil {
			return err
		}
	}
	return nil
}

func nativeProviderBody(provider, endpoint string, raw []byte, upstreamModel string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil || body == nil {
		return nil, fmt.Errorf("native batch request body is invalid")
	}
	for _, key := range []string{
		"models", "provider", "metadata", "trace", "session_id", "tags",
		"plugins", "depth", "stream_options", "service_tier", "user",
	} {
		delete(body, key)
	}
	body["model"] = upstreamModel
	if endpoint == "/v1/chat/completions" {
		normalizeNativeChatTokenLimit(body, provider)
		if reasoning, ok := body["reasoning"].(map[string]any); ok {
			if _, present := body["reasoning_effort"]; !present {
				if effort, present := reasoning["effort"]; present {
					body["reasoning_effort"] = effort
				}
			}
		}
		delete(body, "reasoning")
		body["stream"] = false
	} else {
		delete(body, "stream")
	}
	return body, nil
}

func normalizeNativeChatTokenLimit(body map[string]any, provider string) {
	var value any
	found := false
	for _, key := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		if candidate, present := body[key]; present && !found {
			value = candidate
			found = true
		}
		delete(body, key)
	}
	if !found {
		return
	}
	target := "max_tokens"
	if strings.EqualFold(strings.TrimSpace(provider), "openai") {
		target = "max_completion_tokens"
	}
	body[target] = value
}

func parseOpenAIBatchResultStream(
	reader io.Reader,
	isErrorFile bool,
	token string,
	consume func(NativeProviderResult) error,
) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxResponseBytes)
	for scanner.Scan() {
		var line struct {
			CustomID string `json:"custom_id"`
			Response *struct {
				StatusCode int             `json:"status_code"`
				RequestID  string          `json:"request_id"`
				Body       json.RawMessage `json:"body"`
			} `json:"response"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			return fmt.Errorf("%w: result line is not JSON", ErrNativeInvalidResult)
		}
		index, err := nativeResultIndex(token, line.CustomID)
		if err != nil {
			return err
		}
		result := NativeProviderResult{Index: index, Error: cloneRaw(line.Error)}
		if line.Response != nil {
			result.StatusCode = line.Response.StatusCode
			result.RequestID = line.Response.RequestID
			result.Body = cloneRaw(line.Response.Body)
		}
		if isErrorFile && len(result.Error) == 0 {
			result.Error = json.RawMessage(`{"message":"provider batch item failed","type":"provider_error"}`)
		}
		if err := consume(result); err != nil {
			clear(result.Body)
			clear(result.Error)
			return err
		}
		clear(result.Body)
		clear(result.Error)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%w: result line exceeds the response limit", ErrNativeInvalidResult)
		}
		return fmt.Errorf("native batch result is too large or unreadable")
	}
	return nil
}

func nativeResultID(token string, index int) string {
	return token + "_item_" + strconv.Itoa(index)
}

func nativeResultIndex(token, customID string) (int, error) {
	prefix := token + "_item_"
	value := strings.TrimPrefix(customID, prefix)
	if value == customID || value == "" {
		return 0, fmt.Errorf("%w: result has unknown custom id", ErrNativeInvalidResult)
	}
	index, err := strconv.Atoi(value)
	if err != nil || index < 0 {
		return 0, fmt.Errorf("%w: result has invalid custom id", ErrNativeInvalidResult)
	}
	return index, nil
}

func cloneRaw(value json.RawMessage) json.RawMessage {
	if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}

func drainResponse(body io.Reader) { _, _ = io.Copy(io.Discard, io.LimitReader(body, 64*1024)) }

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
