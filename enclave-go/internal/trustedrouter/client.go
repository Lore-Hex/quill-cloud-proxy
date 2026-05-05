// Package trustedrouter is the metadata-only control-plane client used by the
// attested gateway. It sends API-key lookup hashes, model/routing preferences,
// and token counts; it never sends prompt or completion text.
package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const internalTokenHeader = "x-trustedrouter-internal-token"

type Client struct {
	baseURL       string
	internalToken string
	httpc         *http.Client
	region        string
}

func NewFromEnv() *Client {
	return &Client{
		baseURL:       strings.TrimRight(os.Getenv("TR_CONTROL_PLANE_BASE_URL"), "/"),
		internalToken: os.Getenv("TR_INTERNAL_GATEWAY_TOKEN"),
		region:        os.Getenv("TR_REGION"),
		httpc:         &http.Client{Timeout: 30 * time.Second},
	}
}

func NewFromBootstrap(boot *qtypes.BootstrapData) *Client {
	baseURL := strings.TrimRight(os.Getenv("TR_CONTROL_PLANE_BASE_URL"), "/")
	if baseURL == "" && boot != nil {
		baseURL = strings.TrimRight(boot.TrustedRouterBaseURL, "/")
	}
	internalToken := os.Getenv("TR_INTERNAL_GATEWAY_TOKEN")
	if internalToken == "" && boot != nil {
		internalToken = boot.TrustedRouterInternalToken
	}
	region := os.Getenv("TR_REGION")
	if region == "" && boot != nil {
		region = boot.Region
	}
	return &Client{
		baseURL:       baseURL,
		internalToken: strings.TrimSpace(internalToken),
		region:        region,
		httpc:         &http.Client{Timeout: 30 * time.Second},
	}
}

func New(baseURL, internalToken string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		internalToken: internalToken,
		httpc:         httpc,
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.baseURL != "" && c.internalToken != ""
}

type Authorization struct {
	AuthorizationID       string                             `json:"authorization_id"`
	WorkspaceID           string                             `json:"workspace_id"`
	APIKeyHash            string                             `json:"api_key_hash"`
	Model                 string                             `json:"model"`
	EndpointID            string                             `json:"endpoint_id"`
	Provider              string                             `json:"provider"`
	UsageType             string                             `json:"usage_type"`
	LimitUsageType        string                             `json:"limit_usage_type"`
	BYOKSecretRef         string                             `json:"byok_secret_ref"`
	BYOKEncryptedSecret   *byokcache.EncryptedSecretEnvelope `json:"byok_encrypted_secret"`
	BYOKCacheKey          string                             `json:"byok_cache_key"`
	RouteCandidates       []RouteCandidate                   `json:"route_candidates"`
	BroadcastDestinations []BroadcastDestination             `json:"broadcast_destinations"`
}

type RouteCandidate struct {
	EndpointID          string                             `json:"endpoint_id"`
	Model               string                             `json:"model"`
	Provider            string                             `json:"provider"`
	UsageType           string                             `json:"usage_type"`
	BYOKSecretRef       string                             `json:"byok_secret_ref"`
	BYOKEncryptedSecret *byokcache.EncryptedSecretEnvelope `json:"byok_encrypted_secret"`
	BYOKCacheKey        string                             `json:"byok_cache_key"`
}

type BroadcastDestination struct {
	ID               string                             `json:"id"`
	Type             string                             `json:"type"`
	Endpoint         string                             `json:"endpoint"`
	Method           string                             `json:"method"`
	IncludeContent   bool                               `json:"include_content"`
	APIKeyContext    string                             `json:"api_key_context"`
	HeadersContext   string                             `json:"headers_context"`
	EncryptedAPIKey  *byokcache.EncryptedSecretEnvelope `json:"encrypted_api_key"`
	EncryptedHeaders *byokcache.EncryptedSecretEnvelope `json:"encrypted_headers"`
}

type Usage struct {
	RequestID         string
	InputTokens       int
	OutputTokens      int
	ElapsedSeconds    float64
	FirstTokenSeconds float64
	UsageEstimated    bool
	FinishReason      string
	Streamed          bool
	RouteType         string
	User              string
	SessionID         string
	Trace             map[string]any
	Metadata          map[string]any
}

func (c *Client) Authorize(ctx context.Context, bearer string, req *qtypes.OpenAIChatRequest) (*Authorization, error) {
	return c.AuthorizeWithRoute(ctx, bearer, req, "chat.completions")
}

func (c *Client) ValidateKey(ctx context.Context, bearer string, routeType string) error {
	body := map[string]any{
		"api_key_lookup_hash": lookupHash(bearer),
	}
	if routeType != "" {
		body["route_type"] = routeType
	}
	var decoded map[string]any
	return c.postJSON(ctx, "/internal/gateway/validate", body, &decoded)
}

func (c *Client) AuthorizeWithRoute(ctx context.Context, bearer string, req *qtypes.OpenAIChatRequest, routeType string) (*Authorization, error) {
	body := map[string]any{
		"api_key_lookup_hash":    lookupHash(bearer),
		"model":                  req.Model,
		"estimated_input_tokens": EstimateInputTokens(req),
		"max_output_tokens":      outputTokenEstimate(req),
		"max_tokens":             req.MaxTokens,
		"region":                 c.region,
		"route_type":             routeType,
	}
	if len(req.Models) > 0 {
		body["models"] = req.Models
	}
	if req.Provider != nil {
		body["provider"] = req.Provider
	}
	if req.User != "" {
		body["user"] = req.User
	}
	if req.SessionID != "" {
		body["session_id"] = req.SessionID
	}
	if req.Trace != nil {
		body["trace"] = req.Trace
	}
	if req.Metadata != nil {
		body["metadata"] = req.Metadata
	}
	var decoded struct {
		Data Authorization `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/authorize", body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

type SettleResult struct {
	GenerationID     string  `json:"generation_id"`
	CostMicrodollars int     `json:"cost_microdollars"`
	Cost             float64 `json:"cost"`
	UsageType        string  `json:"usage_type"`
	Model            string  `json:"model"`
	Provider         string  `json:"provider"`
	Region           string  `json:"region"`
}

func (c *Client) Settle(ctx context.Context, auth *Authorization, usage Usage) (*SettleResult, error) {
	if auth == nil {
		return nil, fmt.Errorf("trustedrouter: nil authorization")
	}
	finishReason := usage.FinishReason
	if finishReason == "" {
		finishReason = "stop"
	}
	body := map[string]any{
		"authorization_id":     auth.AuthorizationID,
		"actual_input_tokens":  usage.InputTokens,
		"actual_output_tokens": usage.OutputTokens,
		"request_id":           usage.RequestID,
		"finish_reason":        finishReason,
		"status":               "success",
		"streamed":             usage.Streamed,
		"usage_estimated":      usage.UsageEstimated,
		"elapsed_seconds":      usage.ElapsedSeconds,
		"selected_model":       auth.Model,
		"selected_endpoint":    auth.EndpointID,
		"app":                  "attested-gateway",
	}
	if usage.RouteType != "" {
		body["route_type"] = usage.RouteType
	}
	if usage.User != "" {
		body["user"] = usage.User
	}
	if usage.SessionID != "" {
		body["session_id"] = usage.SessionID
	}
	if usage.Trace != nil {
		body["trace"] = usage.Trace
	}
	if usage.Metadata != nil {
		body["metadata"] = usage.Metadata
	}
	if usage.FirstTokenSeconds > 0 {
		body["first_token_seconds"] = usage.FirstTokenSeconds
	}
	var decoded struct {
		Data SettleResult `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/settle", body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) Refund(ctx context.Context, auth *Authorization, status int, errorType string, elapsedSeconds float64) error {
	if auth == nil {
		return nil
	}
	if status < 100 {
		status = 502
	}
	if errorType == "" {
		errorType = "provider_error"
	}
	body := map[string]any{
		"authorization_id":  auth.AuthorizationID,
		"error_status":      status,
		"error_type":        errorType,
		"elapsed_seconds":   maxFloat(elapsedSeconds, 0.001),
		"streamed":          true,
		"selected_model":    auth.Model,
		"selected_endpoint": auth.EndpointID,
		"app":               "attested-gateway",
	}
	var decoded map[string]any
	return c.postJSON(ctx, "/internal/gateway/refund", body, &decoded)
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(internalTokenHeader, c.internalToken)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("trustedrouter: post %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("trustedrouter: read %s error body: %w", path, readErr)
		}
		return fmt.Errorf("trustedrouter: %s http %d: %s", path, resp.StatusCode, errBody)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func lookupHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func EstimateInputTokens(req *qtypes.OpenAIChatRequest) int {
	total := 0
	for _, message := range req.Messages {
		total += len(message.Content)/4 + 4
	}
	if total < 1 {
		return 1
	}
	return total
}

func outputTokenEstimate(req *qtypes.OpenAIChatRequest) int {
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		return *req.MaxTokens
	}
	return 512
}

func EstimateOutputTokensFromBytes(n int) int {
	if n <= 0 {
		return 1
	}
	tokens := n / 4
	if tokens < 1 {
		return 1
	}
	return tokens
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
