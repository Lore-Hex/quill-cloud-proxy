package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	gcsAPIBase       = "https://storage.googleapis.com/storage/v1"
	gcsUploadBase    = "https://storage.googleapis.com/upload/storage/v1"
	maxGCSObjectSize = 256 * 1024 * 1024
)

var (
	ErrNotFound     = errors.New("batch object not found")
	ErrPrecondition = errors.New("batch object precondition failed")
)

type StoredObject struct {
	Name       string
	Data       []byte
	Generation int64
}

type ObjectMeta struct {
	Name       string
	Generation int64
}

type PutCondition struct {
	// Generation 0 means create-only. A positive value means compare-and-set.
	Generation int64
}

type ObjectStore interface {
	Get(context.Context, string) (StoredObject, error)
	Put(context.Context, string, []byte, PutCondition) (StoredObject, error)
	Delete(context.Context, string, int64) error
	List(context.Context, string, int) ([]ObjectMeta, error)
}

type AccessTokenSource interface {
	Token(context.Context) (string, error)
}

type GCSStore struct {
	bucket         string
	httpc          *http.Client
	tokens         AccessTokenSource
	maxObjectBytes int64
}

func NewGCSStoreWithTokenSource(bucket string, tokens AccessTokenSource) *GCSStore {
	httpc := &http.Client{Timeout: 45 * time.Second}
	return &GCSStore{
		bucket:         strings.TrimSpace(strings.TrimPrefix(bucket, "gs://")),
		httpc:          httpc,
		tokens:         tokens,
		maxObjectBytes: maxGCSObjectSize,
	}
}

func NewGCSStoreForTest(bucket string, httpc *http.Client, tokens AccessTokenSource) *GCSStore {
	return &GCSStore{bucket: bucket, httpc: httpc, tokens: tokens, maxObjectBytes: maxGCSObjectSize}
}

func (s *GCSStore) Get(ctx context.Context, name string) (StoredObject, error) {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return StoredObject{}, fmt.Errorf("batch gcs token: %w", err)
	}
	reqURL := fmt.Sprintf("%s/b/%s/o/%s?alt=media", gcsAPIBase, url.PathEscape(s.bucket), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return StoredObject{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return StoredObject{}, fmt.Errorf("batch gcs get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return StoredObject{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return StoredObject{}, gcsStatusError("get", resp)
	}
	maxObjectBytes := s.maxObjectBytes
	if maxObjectBytes <= 0 || maxObjectBytes > maxGCSObjectSize {
		maxObjectBytes = maxGCSObjectSize
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxObjectBytes+1))
	if err != nil {
		return StoredObject{}, fmt.Errorf("batch gcs read: %w", err)
	}
	if int64(len(data)) > maxObjectBytes {
		return StoredObject{}, fmt.Errorf("batch gcs get: object too large")
	}
	generation, err := strconv.ParseInt(resp.Header.Get("X-Goog-Generation"), 10, 64)
	if err != nil || generation <= 0 {
		return StoredObject{}, fmt.Errorf("batch gcs get: missing generation")
	}
	return StoredObject{Name: name, Data: data, Generation: generation}, nil
}

func (s *GCSStore) Put(ctx context.Context, name string, data []byte, condition PutCondition) (StoredObject, error) {
	maxObjectBytes := s.objectLimit()
	if int64(len(data)) > maxObjectBytes {
		return StoredObject{}, fmt.Errorf("batch gcs put: object too large")
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return StoredObject{}, fmt.Errorf("batch gcs token: %w", err)
	}
	values := url.Values{"uploadType": {"media"}, "name": {name}}
	values.Set("ifGenerationMatch", strconv.FormatInt(condition.Generation, 10))
	reqURL := fmt.Sprintf("%s/b/%s/o?%s", gcsUploadBase, url.PathEscape(s.bucket), values.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return StoredObject{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.httpc.Do(req)
	if err != nil {
		return StoredObject{}, fmt.Errorf("batch gcs put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		return StoredObject{}, ErrPrecondition
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return StoredObject{}, gcsStatusError("put", resp)
	}
	var metadata struct {
		Generation string `json:"generation"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&metadata); err != nil {
		return StoredObject{}, fmt.Errorf("batch gcs put metadata: %w", err)
	}
	generation, err := strconv.ParseInt(metadata.Generation, 10, 64)
	if err != nil || generation <= 0 {
		return StoredObject{}, fmt.Errorf("batch gcs put: invalid generation")
	}
	return StoredObject{Name: name, Data: append([]byte(nil), data...), Generation: generation}, nil
}

func (s *GCSStore) Delete(ctx context.Context, name string, generation int64) error {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("batch gcs token: %w", err)
	}
	values := url.Values{}
	if generation > 0 {
		values.Set("ifGenerationMatch", strconv.FormatInt(generation, 10))
	}
	reqURL := fmt.Sprintf("%s/b/%s/o/%s", gcsAPIBase, url.PathEscape(s.bucket), url.PathEscape(name))
	if query := values.Encode(); query != "" {
		reqURL += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("batch gcs delete: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	case http.StatusPreconditionFailed:
		return ErrPrecondition
	default:
		return gcsStatusError("delete", resp)
	}
}

func (s *GCSStore) List(ctx context.Context, prefix string, limit int) ([]ObjectMeta, error) {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("batch gcs token: %w", err)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	values := url.Values{
		"prefix":     {prefix},
		"maxResults": {strconv.Itoa(limit)},
		"fields":     {"items(name,generation)"},
	}
	reqURL := fmt.Sprintf("%s/b/%s/o?%s", gcsAPIBase, url.PathEscape(s.bucket), values.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("batch gcs list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, gcsStatusError("list", resp)
	}
	var decoded struct {
		Items []struct {
			Name       string `json:"name"`
			Generation string `json:"generation"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("batch gcs list decode: %w", err)
	}
	out := make([]ObjectMeta, 0, len(decoded.Items))
	for _, item := range decoded.Items {
		generation, err := strconv.ParseInt(item.Generation, 10, 64)
		if err != nil || generation <= 0 || item.Name == "" {
			continue
		}
		out = append(out, ObjectMeta{Name: item.Name, Generation: generation})
	}
	return out, nil
}

func (s *GCSStore) objectLimit() int64 {
	if s.maxObjectBytes <= 0 || s.maxObjectBytes > maxGCSObjectSize {
		return maxGCSObjectSize
	}
	return s.maxObjectBytes
}

func gcsStatusError(operation string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("batch gcs %s status %d: %s", operation, resp.StatusCode, strings.TrimSpace(string(body)))
}
