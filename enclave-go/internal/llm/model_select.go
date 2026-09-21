package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

const telluvianSelectorURL = "https://api.telluvian.ai/v1/modelSelect"
const maxSelectionResponseBytes = 16 << 10
const maxSelectionInputBytes = 1 << 20
const selectionTimeout = 5 * time.Second

// ModelSelection is a recommendation, not routing authority. The caller must
// resolve Model against its own catalog and authorize the resulting route.
// Telluvian currently reports no usage or fee; callers must not infer zero cost.
type ModelSelection struct {
	Model     string `json:"model"`
	Reasoning struct {
		Effort string `json:"effort"`
	} `json:"reasoning"`
	SessionID string `json:"sessionId"`
}

// SelectionError is content-free: provider bodies and transport errors can
// contain the prompt or a credential and must never enter logs or responses.
type SelectionError struct {
	Class  string
	Status int
}

func (e *SelectionError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("telluvian selection: %s (%d)", e.Class, e.Status)
	}
	return "telluvian selection: " + e.Class
}

// TelluvianSelector uses the caller's cloud-specific transport. It owns no
// mutable per-request state; a shared instance reuses pooled TLS connections.
type TelluvianSelector struct {
	key  string
	http *http.Client
}

func NewTelluvianSelector(key string, client *http.Client) (*TelluvianSelector, error) {
	if strings.TrimSpace(key) == "" || client == nil {
		return nil, &SelectionError{Class: "configuration"}
	}
	copy := *client
	// Never forward the prompt or operator key to a redirected authority.
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copy.Timeout = selectionTimeout
	return &TelluvianSelector{key: key, http: &copy}, nil
}

var selectionModelPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]*(/[a-zA-Z0-9][a-zA-Z0-9._+-]*)?$`)

// Select executes exactly one paid attempt. Neither 429 nor ambiguous network
// errors are retried, because the selector has no documented idempotency API.
func (s *TelluvianSelector) Select(ctx context.Context, messages string, xPerf float64) (*ModelSelection, error) {
	if s == nil || s.http == nil || s.key == "" {
		return nil, &SelectionError{Class: "configuration"}
	}
	if strings.TrimSpace(messages) == "" || len(messages) > maxSelectionInputBytes || !(xPerf >= 0 && xPerf <= 1) {
		return nil, &SelectionError{Class: "invalid_request"}
	}
	body, err := json.Marshal(struct {
		Messages string  `json:"messages"`
		XPerf    float64 `json:"xPerf"`
	}{Messages: messages, XPerf: xPerf})
	if err != nil {
		return nil, &SelectionError{Class: "invalid_request"}
	}
	ctx, cancel := context.WithTimeout(ctx, selectionTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telluvianSelectorURL, bytes.NewReader(body))
	if err != nil {
		return nil, &SelectionError{Class: "configuration"}
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TrustedRouter/1.0")
	response, err := s.http.Do(req)
	if err != nil {
		class := "transport"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			class = "deadline"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			class = "canceled"
		}
		return nil, &SelectionError{Class: class}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxSelectionResponseBytes))
		return nil, &SelectionError{Class: "http_status", Status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxSelectionResponseBytes+1))
	if err != nil {
		return nil, &SelectionError{Class: "body_read"}
	}
	if len(raw) > maxSelectionResponseBytes {
		return nil, &SelectionError{Class: "response_size"}
	}
	if err := decide.CheckNoDuplicateKeys(raw); err != nil {
		return nil, &SelectionError{Class: "invalid_response"}
	}
	var selection ModelSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		return nil, &SelectionError{Class: "invalid_response"}
	}
	if !selectionModelPattern.MatchString(selection.Model) || len(selection.Model) > 200 || strings.HasPrefix(strings.ToLower(selection.Model), "trustedrouter/") || len(selection.SessionID) > 200 {
		return nil, &SelectionError{Class: "invalid_response"}
	}
	switch selection.Reasoning.Effort {
	case "", "none", "minimal", "low", "medium", "high", "xhigh", "max":
	default:
		return nil, &SelectionError{Class: "invalid_response"}
	}
	return &selection, nil
}
