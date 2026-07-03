// Package trustedrouter is the metadata-only control-plane client used by the
// attested gateway. It sends API-key lookup hashes, model/routing preferences,
// and token counts; it never sends prompt or completion text.
package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const internalTokenHeader = "x-trustedrouter-internal-token"

const imageOutputTokenEstimate = 1290

var imageDataURLPattern = regexp.MustCompile(`data:image/[^;"\s]+;base64,[A-Za-z0-9+/=_-]+`)

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
		httpc:         newControlPlaneHTTPClient(),
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
		httpc:         newControlPlaneHTTPClient(),
	}
}

func New(baseURL, internalToken string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = newControlPlaneHTTPClient()
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
	UpstreamModel         string                             `json:"upstream_model"`
	EndpointID            string                             `json:"endpoint_id"`
	Provider              string                             `json:"provider"`
	UsageType             string                             `json:"usage_type"`
	LimitUsageType        string                             `json:"limit_usage_type"`
	BYOKSecretRef         string                             `json:"byok_secret_ref"`
	BYOKEncryptedSecret   *byokcache.EncryptedSecretEnvelope `json:"byok_encrypted_secret"`
	BYOKCacheKey          string                             `json:"byok_cache_key"`
	RouteCandidates       []RouteCandidate                   `json:"route_candidates"`
	BroadcastDestinations []BroadcastDestination             `json:"broadcast_destinations"`
	CustomModel           *CustomModel                       `json:"custom_model"`
}

type CustomModel struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	BaseModelID  string `json:"base_model_id"`
	HiddenPrompt string `json:"hidden_prompt"`
	Revision     int    `json:"revision"`
}

type RouteCandidate struct {
	EndpointID          string                             `json:"endpoint_id"`
	Model               string                             `json:"model"`
	UpstreamModel       string                             `json:"upstream_model"`
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

type ControlPlaneError struct {
	Path       string
	StatusCode int
	Message    string
	Type       string
	Body       string
	// Retry-After from the control plane (e.g. a per-key window spend limit
	// 429 carries seconds-until-the-window-resets). Relayed to the client so
	// agents can back off precisely instead of guessing.
	RetryAfter string
}

func (e *ControlPlaneError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return fmt.Sprintf("trustedrouter: %s http %d: %s", e.Path, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("trustedrouter: %s http %d: %s", e.Path, e.StatusCode, e.Body)
}

type Usage struct {
	RequestID         string
	InputTokens       int
	OutputTokens      int
	ElapsedSeconds    float64
	FirstTokenSeconds float64
	UsageEstimated    bool
	ReasoningTokens   int
	FinishReason      string
	Streamed          bool
	RouteType         string
	SelectedModel     string
	SelectedEndpoint  string
	User              string
	SessionID         string
	Trace             map[string]any
	Metadata          map[string]any
	// Prompt-cache token counts when the provider reported them. Sent to
	// settle for visibility (GatewaySettleRequest is extra="allow");
	// cache-aware pricing is a control-plane follow-up — today cached
	// input still bills at the full input rate.
	CacheReadInputTokens     int
	CacheCreationInputTokens int
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

func (c *Client) ResolveCustomModel(ctx context.Context, bearer string, model string, routeType string) (*Authorization, error) {
	body := map[string]any{
		"api_key_lookup_hash": lookupHash(bearer),
		"model":               model,
	}
	if routeType != "" {
		body["route_type"] = routeType
	}
	var decoded struct {
		Data Authorization `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/resolve-custom-model", body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
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
	if req.IdempotencyKey != "" {
		body["idempotency_key"] = req.IdempotencyKey
	}
	if len(req.Models) > 0 {
		body["models"] = req.Models
	}
	if req.Provider != nil {
		body["provider"] = req.Provider
	}
	if modalities := qtypes.RequestInputModalities(req); len(modalities) > 0 {
		body["input_modalities"] = modalities
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

// AuthorizeEmbeddings authorizes a POST /v1/embeddings request. Embeddings
// have no completion phase, so max_output_tokens is the schema minimum (1)
// and the per-endpoint completion price is 0 — the cost estimate falls out
// of the input tokens alone. Metadata-only, like AuthorizeWithRoute: model,
// token count, region — never the input text.
func (c *Client) AuthorizeEmbeddings(ctx context.Context, bearer string, req *qtypes.EmbeddingRequest, inputTokens int) (*Authorization, error) {
	if inputTokens < 1 {
		inputTokens = 1
	}
	body := map[string]any{
		"api_key_lookup_hash":    lookupHash(bearer),
		"model":                  req.Model,
		"estimated_input_tokens": inputTokens,
		"max_output_tokens":      1,
		"region":                 c.region,
		"route_type":             "embeddings",
	}
	if req.IdempotencyKey != "" {
		body["idempotency_key"] = req.IdempotencyKey
	}
	if req.User != "" {
		body["user"] = req.User
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
	selectedModel := strings.TrimSpace(usage.SelectedModel)
	if selectedModel == "" {
		selectedModel = auth.Model
	}
	selectedEndpoint := strings.TrimSpace(usage.SelectedEndpoint)
	if selectedEndpoint == "" {
		selectedEndpoint = auth.EndpointID
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
		"selected_model":       selectedModel,
		"selected_endpoint":    selectedEndpoint,
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
	if usage.ReasoningTokens > 0 {
		body["reasoning_tokens"] = usage.ReasoningTokens
	}
	if usage.CacheReadInputTokens > 0 {
		body["cache_read_input_tokens"] = usage.CacheReadInputTokens
	}
	if usage.CacheCreationInputTokens > 0 {
		body["cache_creation_input_tokens"] = usage.CacheCreationInputTokens
	}
	var decoded struct {
		Data SettleResult `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/settle", body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) Refund(ctx context.Context, auth *Authorization, status int, errorType string, elapsedSeconds float64, metadata map[string]any) error {
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
	if metadata != nil {
		body["metadata"] = metadata
	}
	var decoded map[string]any
	return c.postJSON(ctx, "/internal/gateway/refund", body, &decoded)
}

// FetchImage asks the control plane to fetch a remote image URL on the
// enclave's behalf. Used on AWS Nitro builds where the enclave has NO
// network stack of its own — the parent's vsock-proxy daemon only
// knows about a small allowlist of pre-provisioned upstream hosts
// (api.anthropic.com etc., plus this client's own trustedrouter.com
// tunnel on port 8040). User-supplied image URLs go through the
// control plane, which does the DNS resolve + SSRF check + HTTP fetch
// + size cap server-side and returns base64+media_type back over the
// existing TLS-passthrough vsock tunnel.
//
// On GCP confidential VMs the enclave has direct network access, so
// llm/multimodal_direct.go handles fetches inline and this method is
// not used. Both paths share the same Anthropic image-source shape
// downstream of llm.normalizeImageBytes.
func (c *Client) FetchImage(ctx context.Context, url string) (string, []byte, error) {
	if !c.Enabled() {
		return "", nil, fmt.Errorf("trustedrouter: control plane not configured")
	}
	body := map[string]any{"url": url}
	var decoded struct {
		Data struct {
			MediaType  string `json:"media_type"`
			DataBase64 string `json:"data_base64"`
		} `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/fetch-image", body, &decoded); err != nil {
		return "", nil, err
	}
	if decoded.Data.MediaType == "" || decoded.Data.DataBase64 == "" {
		return "", nil, fmt.Errorf("trustedrouter: empty fetch-image response")
	}
	data, err := base64.StdEncoding.DecodeString(decoded.Data.DataBase64)
	if err != nil {
		return "", nil, fmt.Errorf("trustedrouter: decode fetch-image data: %w", err)
	}
	return decoded.Data.MediaType, data, nil
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
		controlErr := &ControlPlaneError{
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       string(errBody),
			RetryAfter: sanitizeRetryAfter(resp.Header.Get("Retry-After")),
		}
		var envelope struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		if json.Unmarshal(errBody, &envelope) == nil {
			controlErr.Message = strings.TrimSpace(envelope.Error.Message)
			controlErr.Type = strings.TrimSpace(envelope.Error.Type)
		}
		return controlErr
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// KeyInfo serves the /v1/key passthrough: agents read their own key's budget
// (limits, per-window remaining, resets_at) through the attested endpoint they
// send inference to. The RAW BEARER NEVER LEAVES THE ENCLAVE — same contract
// as authorize: the control plane's /internal/gateway/key is keyed by the
// key's lookup hash + the internal gateway token. Returns the control-plane
// status + JSON body verbatim (the caller allowlists statuses).
func (c *Client) KeyInfo(ctx context.Context, bearer string) (int, []byte, error) {
	payload, err := json.Marshal(map[string]string{
		"api_key_lookup_hash": lookupHash(bearer),
	})
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.baseURL+"/internal/gateway/key", bytes.NewReader(payload),
	)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(internalTokenHeader, c.internalToken)
	resp, err := c.httpc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("trustedrouter: post /internal/gateway/key: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("trustedrouter: read /internal/gateway/key body: %w", err)
	}
	return resp.StatusCode, body, nil
}

// sanitizeRetryAfter keeps only a bare delta-seconds value (the form the
// control plane sends — seconds until a spend window resets). Anything else
// (an HTTP-date we don't emit, or any CRLF/control chars) is dropped, so a
// relayed Retry-After can never inject into the enclave's hand-written HTTP
// response headers (codex #93 enclave review).
func sanitizeRetryAfter(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return v
}

func lookupHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func EstimateInputTokens(req *qtypes.OpenAIChatRequest) int {
	total := 0
	for _, message := range req.Messages {
		total += qtypes.ContentTokenEstimate(message.Content) + 4
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

func EstimateOutputTokens(text string) int {
	imageCount := len(imageDataURLPattern.FindAllStringIndex(text, -1))
	textOnly := imageDataURLPattern.ReplaceAllString(text, "")
	tokens := len(textOnly)/4 + imageCount*imageOutputTokenEstimate
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
