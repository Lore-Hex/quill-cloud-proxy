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
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const internalTokenHeader = "x-trustedrouter-internal-token"

const trustedSyntheticApp = "TrustedRouter Synthetic"

const imageOutputTokenEstimate = 1290

const (
	publicModelsFreshTTL = 5 * time.Minute
	publicModelsStaleTTL = 30 * time.Minute
	publicModelsMaxBytes = 8 << 20
)

var imageDataURLPattern = regexp.MustCompile(`data:image/[^;"\s]+;base64,[A-Za-z0-9+/=_-]+`)

var requestLogIDPattern = regexp.MustCompile(`^rlog_[0-9a-f]{32}$`)

type requestLogIDContextKey struct{}

type clientContextContextKey struct{}

// WithRequestLogID associates the enclave audit-log ID with control-plane
// settlement and refund calls made for the request.
func WithRequestLogID(ctx context.Context, requestLogID string) context.Context {
	return context.WithValue(ctx, requestLogIDContextKey{}, requestLogID)
}

func requestLogIDFromContext(ctx context.Context) string {
	requestLogID, _ := ctx.Value(requestLogIDContextKey{}).(string)
	if !requestLogIDPattern.MatchString(requestLogID) {
		return ""
	}
	return requestLogID
}

// WithClientContext associates bounded, content-free SDK and retry telemetry
// with settlement and refund calls made for the request.
func WithClientContext(ctx context.Context, clientContext *qtypes.ClientContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if clientContext == nil {
		return ctx
	}
	return context.WithValue(ctx, clientContextContextKey{}, clientContext)
}

// ClientContextFromContext returns the client context attached by
// WithClientContext, or nil. Exported so the enclave's settlement retry queue
// can carry the value on its job (the retry worker runs on the queue's own
// context) exactly like the request log id.
func ClientContextFromContext(ctx context.Context) *qtypes.ClientContext {
	if ctx == nil {
		return nil
	}
	clientContext, _ := ctx.Value(clientContextContextKey{}).(*qtypes.ClientContext)
	return clientContext
}

type Client struct {
	// baseURLs is ordered: index 0 is the configured billing authority, and
	// later entries are fallbacks used only when an earlier one cannot be
	// dialled. Observer/status services are never valid entries. See
	// endpoints.go for why only dial failures may advance it.
	baseURLs           []string
	configurationError error
	internalToken      string
	httpc              *http.Client
	region             string
	authorizeRetry     retryPolicy
	modelsMu           sync.Mutex
	modelsBody         []byte
	modelsFetched      time.Time
	imageModelsMu      sync.Mutex
	imageModelsBody    []byte
	imageModelsFetched time.Time
}

func NewFromEnv() *Client {
	baseURLs, configurationError := parseControlPlaneEndpoints(os.Getenv("TR_CONTROL_PLANE_BASE_URL"))
	return &Client{
		baseURLs:           baseURLs,
		configurationError: configurationError,
		internalToken:      os.Getenv("TR_INTERNAL_GATEWAY_TOKEN"),
		region:             os.Getenv("TR_REGION"),
		httpc:              newControlPlaneHTTPClient(),
		authorizeRetry:     defaultAuthorizeRetryPolicy(),
	}
}

func NewFromBootstrap(boot *qtypes.BootstrapData) *Client {
	baseURLs, configurationError := parseControlPlaneEndpoints(os.Getenv("TR_CONTROL_PLANE_BASE_URL"))
	if configurationError == nil && len(baseURLs) == 0 && boot != nil {
		baseURLs, configurationError = parseControlPlaneEndpoints(boot.TrustedRouterBaseURL)
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
		baseURLs:           baseURLs,
		configurationError: configurationError,
		internalToken:      strings.TrimSpace(internalToken),
		region:             region,
		httpc:              newControlPlaneHTTPClient(),
		authorizeRetry:     defaultAuthorizeRetryPolicy(),
	}
}

func New(baseURL, internalToken string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = newControlPlaneHTTPClient()
	}
	baseURLs, configurationError := parseControlPlaneEndpoints(baseURL)
	return &Client{
		baseURLs:           baseURLs,
		configurationError: configurationError,
		internalToken:      internalToken,
		httpc:              httpc,
		authorizeRetry:     defaultAuthorizeRetryPolicy(),
	}
}

func (c *Client) Enabled() bool {
	if c == nil {
		return false
	}
	return c.configurationError != nil || (len(c.baseURLs) > 0 && c.internalToken != "")
}

// ConfigurationError reports a fail-closed control-plane configuration error.
// Callers that own process startup should treat it as fatal so health checks
// cannot stay green while every metered request is guaranteed to fail.
func (c *Client) ConfigurationError() error {
	if c == nil {
		return nil
	}
	return c.configurationError
}

// ProductionConfigurationError rejects both malformed and absent billing
// configuration. Local unit tests may construct a disabled Client explicitly,
// but a deployed enclave must never turn a missing URL or token into the
// legacy unmetered device-key path.
func (c *Client) ProductionConfigurationError() error {
	if c == nil {
		return fmt.Errorf("trustedrouter: control-plane client is nil")
	}
	if c.configurationError != nil {
		return c.configurationError
	}
	if len(c.baseURLs) == 0 {
		return fmt.Errorf("trustedrouter: control-plane endpoint is required")
	}
	if strings.TrimSpace(c.internalToken) == "" {
		return fmt.Errorf("trustedrouter: internal gateway token is required")
	}
	return nil
}

// PublicModels returns the public model catalog through the same attested
// origin clients use for inference. The catalog contains public metadata only;
// this request carries neither a user bearer nor the internal gateway token.
// A short cache avoids turning catalog discovery into a control-plane hot path,
// while a bounded stale copy keeps SDK discovery available during a brief
// control-plane interruption.
func (c *Client) PublicModels(ctx context.Context) ([]byte, error) {
	if c != nil && c.configurationError != nil {
		return nil, c.configurationError
	}
	if c == nil || len(c.baseURLs) == 0 {
		return nil, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
	}

	c.modelsMu.Lock()
	defer c.modelsMu.Unlock()

	now := time.Now()
	if len(c.modelsBody) > 0 && now.Sub(c.modelsFetched) <= publicModelsFreshTTL {
		return append([]byte(nil), c.modelsBody...), nil
	}

	body, err := c.fetchPublicModels(ctx)
	if err == nil {
		c.modelsBody = append(c.modelsBody[:0], body...)
		c.modelsFetched = now
		return append([]byte(nil), c.modelsBody...), nil
	}
	if len(c.modelsBody) > 0 && now.Sub(c.modelsFetched) <= publicModelsStaleTTL {
		fmt.Fprintf(os.Stderr, "enclave.models_stale_fallback err=%q\n", err.Error())
		return append([]byte(nil), c.modelsBody...), nil
	}
	return nil, err
}

func (c *Client) fetchPublicModels(ctx context.Context) ([]byte, error) {
	return c.fetchPublicCatalog(ctx, "/v1/models", "/models", func(body []byte) bool {
		var envelope struct {
			Data []json.RawMessage `json:"data"`
		}
		return json.Unmarshal(body, &envelope) == nil && len(envelope.Data) > 0
	})
}

// PublicImageModels returns the image-only capability catalog with the same
// anonymous, bounded, stale-if-error semantics as PublicModels.
func (c *Client) PublicImageModels(ctx context.Context) ([]byte, error) {
	if c != nil && c.configurationError != nil {
		return nil, c.configurationError
	}
	if c == nil || len(c.baseURLs) == 0 {
		return nil, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
	}
	c.imageModelsMu.Lock()
	defer c.imageModelsMu.Unlock()
	now := time.Now()
	if len(c.imageModelsBody) > 0 && now.Sub(c.imageModelsFetched) <= publicModelsFreshTTL {
		return append([]byte(nil), c.imageModelsBody...), nil
	}
	body, err := c.fetchPublicCatalog(ctx, "/v1/images/models", "/images/models", func(body []byte) bool {
		var envelope struct {
			Data []json.RawMessage `json:"data"`
		}
		return json.Unmarshal(body, &envelope) == nil && len(envelope.Data) > 0
	})
	if err == nil {
		c.imageModelsBody = append(c.imageModelsBody[:0], body...)
		c.imageModelsFetched = now
		return append([]byte(nil), c.imageModelsBody...), nil
	}
	if len(c.imageModelsBody) > 0 && now.Sub(c.imageModelsFetched) <= publicModelsStaleTTL {
		fmt.Fprintf(os.Stderr, "enclave.image_models_stale_fallback err=%q\n", err.Error())
		return append([]byte(nil), c.imageModelsBody...), nil
	}
	return nil, err
}

var publicImageModelIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._:-]+$`)

// PublicImageModelEndpoints relays one public endpoint manifest. Model IDs are
// path data, never a free-form URL; reject traversal and query injection before
// building the control-plane request.
func (c *Client) PublicImageModelEndpoints(ctx context.Context, modelID string) ([]byte, error) {
	modelID = strings.TrimSpace(modelID)
	if !publicImageModelIDPattern.MatchString(modelID) {
		return nil, fmt.Errorf("trustedrouter: invalid image model id")
	}
	path := "/v1/images/models/" + modelID + "/endpoints"
	return c.fetchPublicCatalog(ctx, path, "/images/models/{model}/endpoints", func(body []byte) bool {
		var envelope struct {
			ID        string            `json:"id"`
			Endpoints []json.RawMessage `json:"endpoints"`
		}
		return json.Unmarshal(body, &envelope) == nil && envelope.ID == modelID
	})
}

func (c *Client) fetchPublicCatalog(
	ctx context.Context,
	path string,
	label string,
	valid func([]byte) bool,
) ([]byte, error) {
	if c != nil && c.configurationError != nil {
		return nil, c.configurationError
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var lastErr error
	for _, base := range c.baseURLs {
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, publicCatalogURL(base, path), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("trustedrouter: get %s: %w", label, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, publicModelsMaxBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("trustedrouter: read %s: %w", label, readErr)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("trustedrouter: %s http %d", label, resp.StatusCode)
			continue
		}
		// A 200 is not enough. trustedrouter.com/models is a human-facing HTML
		// page and answers 200 happily; only the content type distinguishes it
		// from the API. Naming the type turns "invalid /models response" into a
		// message that identifies the mistake.
		// Specifically HTML. A 200 text/html body is the signature of hitting
		// the human-facing page instead of the API, and the JSON decode below
		// would report it as a malformed catalog. Anything else — including a
		// missing or sloppy content type — is left to the decoder, because a
		// control plane serving valid JSON without the header is still correct.
		if ct := resp.Header.Get("Content-Type"); strings.Contains(strings.ToLower(ct), "text/html") {
			lastErr = fmt.Errorf("trustedrouter: %s returned HTML (%q), not the API — wrong path?", label, ct)
			continue
		}
		if len(body) > publicModelsMaxBytes {
			lastErr = fmt.Errorf("trustedrouter: %s response too large", label)
			continue
		}
		if valid == nil || !valid(body) {
			lastErr = fmt.Errorf("trustedrouter: invalid %s response", label)
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("trustedrouter: no control-plane endpoint configured")
	}
	return nil, lastErr
}

// primaryBaseURL is the configured billing authority used unless it cannot be
// dialled at all.
func (c *Client) primaryBaseURL() string {
	if c == nil || len(c.baseURLs) == 0 {
		return ""
	}
	return c.baseURLs[0]
}

type Authorization struct {
	AuthorizationID                       string                             `json:"authorization_id"`
	WorkspaceID                           string                             `json:"workspace_id"`
	APIKeyHash                            string                             `json:"api_key_hash"`
	Model                                 string                             `json:"model"`
	UpstreamModel                         string                             `json:"upstream_model"`
	EndpointID                            string                             `json:"endpoint_id"`
	Provider                              string                             `json:"provider"`
	ProviderName                          string                             `json:"provider_name"`
	WaferZDRRequired                      bool                               `json:"wafer_zdr_required"`
	RequestedModel                        string                             `json:"requested_model"`
	Region                                string                             `json:"region"`
	UsageType                             string                             `json:"usage_type"`
	LimitUsageType                        string                             `json:"limit_usage_type"`
	BYOKSecretRef                         string                             `json:"byok_secret_ref"`
	BYOKEncryptedSecret                   *byokcache.EncryptedSecretEnvelope `json:"byok_encrypted_secret"`
	BYOKCacheKey                          string                             `json:"byok_cache_key"`
	BYOKProvider                          string                             `json:"byok_provider"`
	RouteCandidates                       []RouteCandidate                   `json:"route_candidates"`
	BroadcastDestinations                 []BroadcastDestination             `json:"broadcast_destinations"`
	CustomModel                           *CustomModel                       `json:"custom_model"`
	Tags                                  qtypes.TagMap                      `json:"tags"`
	RequestMetadataVersion                int                                `json:"request_metadata_version"`
	AdditionalCostReservationMicrodollars int                                `json:"additional_cost_reservation_microdollars"`
	NativeBatchEligible                   bool                               `json:"native_batch_eligible"`
	RouteType                             string                             `json:"-"`
	// ControlPlaneEndpoint is enclave-local billing authority state. It is
	// never accepted from or exposed to the control plane or client. A settle
	// or refund must return to the same authority that created the hold.
	ControlPlaneEndpoint    int  `json:"-"`
	ControlPlaneEndpointSet bool `json:"-"`
}

func (a *Authorization) pinControlPlaneEndpoint(endpoint int) {
	if a == nil || endpoint < 0 {
		return
	}
	a.ControlPlaneEndpoint = endpoint
	a.ControlPlaneEndpointSet = true
}

func (a *Authorization) pinnedControlPlaneEndpoint() int {
	if a == nil || !a.ControlPlaneEndpointSet {
		return -1
	}
	return a.ControlPlaneEndpoint
}

// KeyIdentity is metadata-only ownership information returned by the
// control plane's validation endpoint. It is safe for internal operational
// attribution: neither field is a raw credential, prompt, or response.
type KeyIdentity struct {
	WorkspaceID string `json:"workspace_id"`
	APIKeyHash  string `json:"api_key_hash"`
}

type CustomModel struct {
	ID                      string                             `json:"id"`
	Name                    string                             `json:"name"`
	Kind                    string                             `json:"kind"`
	BaseModelID             string                             `json:"base_model_id"`
	HiddenPrompt            string                             `json:"hidden_prompt"`
	UserModelKind           string                             `json:"user_model_kind"`
	OwnerWorkspaceID        string                             `json:"owner_workspace_id"`
	OwnerUserID             string                             `json:"owner_user_id"`
	EndpointURL             string                             `json:"endpoint_url"`
	UpstreamModelID         string                             `json:"upstream_model_id"`
	Revision                int                                `json:"revision"`
	SupportsStreaming       bool                               `json:"supports_streaming"`
	SecretNamespace         string                             `json:"secret_namespace"`
	EndpointEncryptedSecret *byokcache.EncryptedSecretEnvelope `json:"endpoint_encrypted_secret"`
	EndpointSecretPurpose   string                             `json:"endpoint_secret_purpose"`
	SigningEncryptedSecret  *byokcache.EncryptedSecretEnvelope `json:"signing_encrypted_secret"`
	SigningSecretPurpose    string                             `json:"signing_secret_purpose"`
	ConnectTimeoutSeconds   int                                `json:"connect_timeout_seconds"`
	FirstByteTimeoutSeconds int                                `json:"first_byte_timeout_seconds"`
	IdleTimeoutSeconds      int                                `json:"idle_timeout_seconds"`
	TotalTimeoutSeconds     int                                `json:"total_timeout_seconds"`
}

type RouteCandidate struct {
	EndpointID          string                             `json:"endpoint_id"`
	Model               string                             `json:"model"`
	UpstreamModel       string                             `json:"upstream_model"`
	Provider            string                             `json:"provider"`
	ProviderName        string                             `json:"provider_name"`
	WaferZDRRequired    bool                               `json:"wafer_zdr_required"`
	UsageType           string                             `json:"usage_type"`
	BYOKSecretRef       string                             `json:"byok_secret_ref"`
	BYOKEncryptedSecret *byokcache.EncryptedSecretEnvelope `json:"byok_encrypted_secret"`
	BYOKCacheKey        string                             `json:"byok_cache_key"`
	BYOKProvider        string                             `json:"byok_provider"`
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
	// Tags are frozen at authorize; settle never sends client-mutable tags.
	App           string
	HTTPReferer   string
	AppCategories []string
	// Prompt-cache token counts when the provider reported them. Sent to
	// settle for visibility (GatewaySettleRequest is extra="allow");
	// cache-aware pricing is a control-plane follow-up — today cached
	// input still bills at the full input rate.
	CacheReadInputTokens       int
	CacheCreationInputTokens   int
	AdditionalCostMicrodollars int
	ServiceTier                string
	VideoInputMode             string
	VideoDurationSeconds       int
	VideoResolution            string
	VideoAspectRatio           string
	VideoGenerateAudio         bool
}

// RefundAttribution carries the same content-free request identifiers as a
// successful settlement. It never includes prompts, outputs, or credentials.
type RefundAttribution struct {
	User      string
	SessionID string
	Trace     map[string]any
}

func (c *Client) Authorize(ctx context.Context, bearer string, req *qtypes.OpenAIChatRequest) (*Authorization, error) {
	return c.AuthorizeWithRoute(ctx, bearer, req, "chat.completions")
}

func (c *Client) ValidateKey(ctx context.Context, bearer string, routeType string) error {
	_, err := c.ValidateKeyInfo(ctx, bearer, routeType)
	return err
}

// ValidateKeyInfo performs the same side-effect-free key validation as
// ValidateKey and returns the verified workspace/key identity. Error paths in
// the enclave use this after writing the client response so requests rejected
// before billing authorization remain attributable without creating a hold.
func (c *Client) ValidateKeyInfo(ctx context.Context, bearer string, routeType string) (*KeyIdentity, error) {
	body := map[string]any{
		"api_key_lookup_hash": requestLookupHash(ctx, bearer),
	}
	if routeType != "" {
		body["route_type"] = routeType
	}
	var decoded struct {
		Data KeyIdentity `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/validate", body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) ResolveCustomModel(ctx context.Context, bearer string, model string, routeType string) (*Authorization, error) {
	body := map[string]any{
		"api_key_lookup_hash": requestLookupHash(ctx, bearer),
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
	idempotencyKey, err := authorizationIdempotencyKey(req.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"api_key_lookup_hash":    requestLookupHash(ctx, bearer),
		"model":                  req.Model,
		"estimated_input_tokens": EstimateInputTokens(req),
		"max_output_tokens":      outputTokenEstimate(req),
		"max_tokens":             req.MaxTokens,
		"region":                 c.region,
		"route_type":             routeType,
		"idempotency_key":        idempotencyKey,
	}
	if req.RequestFingerprint != "" {
		body["request_fingerprint"] = req.RequestFingerprint
	}
	if req.AdditionalCostReservationMicrodollars > 0 {
		body["additional_cost_reservation_microdollars"] = req.AdditionalCostReservationMicrodollars
	}
	if req.ServiceTier != "" {
		body["service_tier"] = req.ServiceTier
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
	if req.Tags != nil {
		body["tags"] = req.Tags.Values()
	}
	if req.App != "" {
		body["app"] = req.App
	}
	if req.HTTPReferer != "" {
		body["http_referer"] = req.HTTPReferer
	}
	if len(req.AppCategories) > 0 {
		body["app_categories"] = req.AppCategories
	}
	var decoded struct {
		Data Authorization `json:"data"`
	}
	controlPlaneEndpoint, err := c.postJSONWithRetryAtEndpoint(
		ctx, "/internal/gateway/authorize", body, &decoded, c.authorizeRetry,
	)
	if err != nil {
		return nil, err
	}
	decoded.Data.pinControlPlaneEndpoint(controlPlaneEndpoint)
	decoded.Data.RouteType = routeType
	if routeType != "videos" && routeType != "images" && req.AdditionalCostReservationMicrodollars > 0 &&
		decoded.Data.AdditionalCostReservationMicrodollars != req.AdditionalCostReservationMicrodollars {
		_ = c.Refund(ctx, &decoded.Data, 503, "hosted_tool_billing_unavailable", 0.001, nil)
		return nil, &ControlPlaneError{
			Path:       "/internal/gateway/authorize",
			StatusCode: 503,
			Type:       "hosted_tool_billing_unavailable",
			Message:    "hosted-tool billing is not available on the active control plane",
		}
	}
	if routeType == "videos" && decoded.Data.AdditionalCostReservationMicrodollars <= 0 {
		_ = c.Refund(ctx, &decoded.Data, 503, "video_billing_unavailable", 0.001, nil)
		return nil, &ControlPlaneError{
			Path:       "/internal/gateway/authorize",
			StatusCode: 503,
			Type:       "video_billing_unavailable",
			Message:    "video billing is not available on the active control plane",
		}
	}
	if routeType == "images" && req.AdditionalCostReservationMicrodollars > 0 &&
		decoded.Data.AdditionalCostReservationMicrodollars != req.AdditionalCostReservationMicrodollars {
		_ = c.Refund(ctx, &decoded.Data, 503, "image_billing_unavailable", 0.001, nil)
		return nil, &ControlPlaneError{
			Path:       "/internal/gateway/authorize",
			StatusCode: 503,
			Type:       "image_billing_unavailable",
			Message:    "fixed-price image billing is not available on the active control plane",
		}
	}
	if req.Tags != nil && decoded.Data.RequestMetadataVersion < 1 {
		_ = c.Refund(ctx, &decoded.Data, 503, "request_metadata_unavailable", 0.001, nil)
		return nil, &ControlPlaneError{
			Path:       "/internal/gateway/authorize",
			StatusCode: 503,
			Type:       "request_metadata_unavailable",
			Message:    "request tagging is not available on the active control plane",
		}
	}
	if decoded.Data.RequestMetadataVersion >= 1 {
		req.Tags = qtypes.NewRequestTags(decoded.Data.Tags)
	}
	return &decoded.Data, nil
}

// AuthorizeEmbeddings authorizes a POST /v1/embeddings request. Embeddings
// have no completion phase, so max_output_tokens is the schema minimum (1)
// and the per-endpoint completion price is 0 — the cost estimate falls out
// of the input tokens alone. Metadata-only, like AuthorizeWithRoute: model,
// token count, region — never the input text.
func (c *Client) AuthorizeEmbeddings(ctx context.Context, bearer string, req *qtypes.EmbeddingRequest, inputTokens int) (*Authorization, error) {
	return c.AuthorizeEmbeddingsWithRoute(ctx, bearer, req, inputTokens, "embeddings")
}

func (c *Client) AuthorizeEmbeddingsWithRoute(
	ctx context.Context,
	bearer string,
	req *qtypes.EmbeddingRequest,
	inputTokens int,
	routeType string,
) (*Authorization, error) {
	if inputTokens < 1 {
		inputTokens = 1
	}
	if strings.TrimSpace(routeType) == "" {
		routeType = "embeddings"
	}
	idempotencyKey, err := authorizationIdempotencyKey(req.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"api_key_lookup_hash":    requestLookupHash(ctx, bearer),
		"model":                  req.Model,
		"estimated_input_tokens": inputTokens,
		"max_output_tokens":      1,
		"region":                 c.region,
		"route_type":             routeType,
		"idempotency_key":        idempotencyKey,
	}
	if req.User != "" {
		body["user"] = req.User
	}
	if req.SessionID != "" {
		body["session_id"] = req.SessionID
	}
	if req.Metadata != nil {
		body["metadata"] = req.Metadata
	}
	if req.Trace != nil {
		body["trace"] = req.Trace
	}
	if req.Tags != nil {
		body["tags"] = req.Tags.Values()
	}
	if req.App != "" {
		body["app"] = req.App
	}
	if req.HTTPReferer != "" {
		body["http_referer"] = req.HTTPReferer
	}
	if len(req.AppCategories) > 0 {
		body["app_categories"] = req.AppCategories
	}
	var decoded struct {
		Data Authorization `json:"data"`
	}
	controlPlaneEndpoint, err := c.postJSONWithRetryAtEndpoint(
		ctx, "/internal/gateway/authorize", body, &decoded, c.authorizeRetry,
	)
	if err != nil {
		return nil, err
	}
	decoded.Data.pinControlPlaneEndpoint(controlPlaneEndpoint)
	decoded.Data.RouteType = routeType
	if req.Tags != nil && decoded.Data.RequestMetadataVersion < 1 {
		_ = c.Refund(ctx, &decoded.Data, 503, "request_metadata_unavailable", 0.001, nil)
		return nil, &ControlPlaneError{
			Path:       "/internal/gateway/authorize",
			StatusCode: 503,
			Type:       "request_metadata_unavailable",
			Message:    "request tagging is not available on the active control plane",
		}
	}
	if decoded.Data.RequestMetadataVersion >= 1 {
		req.Tags = qtypes.NewRequestTags(decoded.Data.Tags)
	}
	return &decoded.Data, nil
}

type SettleResult struct {
	GenerationID         string  `json:"generation_id"`
	CostMicrodollars     int     `json:"cost_microdollars"`
	Cost                 float64 `json:"cost"`
	InputTokens          int     `json:"input_tokens"`
	OutputTokens         int     `json:"output_tokens"`
	ReasoningTokens      int     `json:"reasoning_tokens"`
	CacheReadInputTokens int     `json:"cache_read_input_tokens"`
	UsageType            string  `json:"usage_type"`
	Model                string  `json:"model"`
	Provider             string  `json:"provider"`
	Region               string  `json:"region"`
	Settled              bool    `json:"settled"`
	AlreadySettled       bool    `json:"already_settled"`
	FinalizationOutcome  string  `json:"finalization_outcome"`
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
	app := usage.App
	if app == "" || strings.EqualFold(app, trustedSyntheticApp) {
		app = "attested-gateway"
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
		"app":                  app,
	}
	if requestLogID := requestLogIDFromContext(ctx); requestLogID != "" {
		body["gateway_request_id"] = requestLogID
	}
	if clientContext := ClientContextFromContext(ctx); clientContext != nil && clientContext.Validate() == nil {
		body["client"] = clientContext.AsBody()
	}
	if usage.AdditionalCostMicrodollars > 0 {
		body["additional_cost_microdollars"] = usage.AdditionalCostMicrodollars
	}
	if usage.RouteType != "" {
		body["route_type"] = usage.RouteType
	}
	if usage.RouteType == "videos" {
		body["video_input_mode"] = usage.VideoInputMode
		body["video_duration_seconds"] = usage.VideoDurationSeconds
		body["video_resolution"] = usage.VideoResolution
		body["video_aspect_ratio"] = usage.VideoAspectRatio
		body["video_generate_audio"] = usage.VideoGenerateAudio
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
	if usage.HTTPReferer != "" {
		body["http_referer"] = usage.HTTPReferer
	}
	if len(usage.AppCategories) > 0 {
		body["app_categories"] = usage.AppCategories
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
	if usage.ServiceTier != "" {
		body["service_tier"] = usage.ServiceTier
	}
	var decoded struct {
		Data SettleResult `json:"data"`
	}
	if _, err := c.postJSONAtEndpoint(
		ctx, "/internal/gateway/settle", body, &decoded, auth.pinnedControlPlaneEndpoint(),
	); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) Refund(ctx context.Context, auth *Authorization, status int, errorType string, elapsedSeconds float64, metadata map[string]any) error {
	_, err := c.RefundDetailed(ctx, auth, status, errorType, elapsedSeconds, metadata)
	return err
}

// RefundDetailed preserves the control plane's idempotency outcome. Most
// real-time callers only need Refund's error, while durable Batch workers must
// distinguish an already-refunded replay from a late refund that lost to a
// successful settlement.
func (c *Client) RefundDetailed(ctx context.Context, auth *Authorization, status int, errorType string, elapsedSeconds float64, metadata map[string]any) (*SettleResult, error) {
	return c.refundDetailed(
		ctx, auth, status, errorType, elapsedSeconds, metadata, RefundAttribution{},
	)
}

// RefundDetailedAttributed preserves content-free request attribution for
// durable workers whose refund may occur long after the original request.
func (c *Client) RefundDetailedAttributed(
	ctx context.Context,
	auth *Authorization,
	status int,
	errorType string,
	elapsedSeconds float64,
	metadata map[string]any,
	attribution RefundAttribution,
) (*SettleResult, error) {
	return c.refundDetailed(
		ctx, auth, status, errorType, elapsedSeconds, metadata, attribution,
	)
}

func (c *Client) refundDetailed(
	ctx context.Context,
	auth *Authorization,
	status int,
	errorType string,
	elapsedSeconds float64,
	metadata map[string]any,
	attribution RefundAttribution,
) (*SettleResult, error) {
	if auth == nil {
		return &SettleResult{}, nil
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
	if requestLogID := requestLogIDFromContext(ctx); requestLogID != "" {
		body["gateway_request_id"] = requestLogID
	}
	if clientContext := ClientContextFromContext(ctx); clientContext != nil && clientContext.Validate() == nil {
		body["client"] = clientContext.AsBody()
	}
	if auth.RouteType != "" {
		body["route_type"] = auth.RouteType
	}
	if metadata != nil {
		body["metadata"] = metadata
	}
	if attribution.User != "" {
		body["user"] = attribution.User
	}
	if attribution.SessionID != "" {
		body["session_id"] = attribution.SessionID
	}
	if attribution.Trace != nil {
		body["trace"] = attribution.Trace
	}
	var decoded struct {
		Data SettleResult `json:"data"`
	}
	if _, err := c.postJSONAtEndpoint(
		ctx, "/internal/gateway/refund", body, &decoded, auth.pinnedControlPlaneEndpoint(),
	); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
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

// postToFirstDialable POSTs to the ordered control-plane endpoints, moving to
// the next ONLY when the current one could not be dialled.
//
// That restriction is the whole safety argument: net/http runs DialContext
// before writing any request byte, so a dial failure proves this request
// reached no server and cannot have escrowed credits or booked usage. Every
// other error is ambiguous — notably a connection dropped mid-response, where
// the server HAS processed the request and we merely failed to read the answer.
// Re-sending that to a DIFFERENT plane with a DIFFERENT database (idempotency
// keys do not travel between them) could reserve or bill twice.
func (c *Client) postToControlPlane(
	ctx context.Context,
	path string,
	body []byte,
	pinnedEndpoint int,
) (*http.Response, int, error) {
	if c != nil && c.configurationError != nil {
		return nil, -1, c.configurationError
	}
	if len(c.baseURLs) == 0 {
		return nil, -1, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
	}
	start, end := 0, len(c.baseURLs)
	if pinnedEndpoint >= 0 {
		if pinnedEndpoint >= len(c.baseURLs) {
			return nil, -1, fmt.Errorf("trustedrouter: invalid control-plane endpoint index %d", pinnedEndpoint)
		}
		start, end = pinnedEndpoint, pinnedEndpoint+1
	}
	for i := start; i < end; i++ {
		base := c.baseURLs[i]
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
		if err != nil {
			return nil, -1, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(internalTokenHeader, c.internalToken)

		resp, err := c.httpc.Do(req)
		if err == nil {
			if pinnedEndpoint < 0 && i > 0 {
				// A silent fallback reads as health: the primary could be down
				// for days while every request quietly succeeds on the standby.
				fmt.Fprintf(os.Stderr,
					"enclave.control_plane_failover path=%q endpoint_index=%d\n", path, i)
			}
			return resp, i, nil
		}
		if pinnedEndpoint >= 0 || !isDialFailure(err) || i == end-1 {
			return nil, -1, fmt.Errorf("trustedrouter: post %s: %w", path, err)
		}
		fmt.Fprintf(os.Stderr,
			"enclave.control_plane_undialable path=%q endpoint_index=%d err=%v\n", path, i, err)
	}
	return nil, -1, fmt.Errorf("trustedrouter: post %s: no endpoint dialable", path)
}

func (c *Client) postToFirstDialable(ctx context.Context, path string, body []byte) (*http.Response, error) {
	resp, _, err := c.postToControlPlane(ctx, path, body, -1)
	return resp, err
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, out any) error {
	_, err := c.postJSONAtEndpoint(ctx, path, payload, out, -1)
	return err
}

// postJSONAtEndpoint returns the endpoint that actually received the request.
// Passing a non-negative endpoint pins the request to that authority. This is
// load-bearing for authorization retries: idempotency is local to one billing
// database, so a retry must never move after an authority has responded.
func (c *Client) postJSONAtEndpoint(
	ctx context.Context,
	path string,
	payload any,
	out any,
	pinnedEndpoint int,
) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return -1, err
	}
	resp, selectedEndpoint, err := c.postToControlPlane(ctx, path, body, pinnedEndpoint)
	if err != nil {
		return selectedEndpoint, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return selectedEndpoint, fmt.Errorf("trustedrouter: read %s error body: %w", path, readErr)
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
		return selectedEndpoint, controlErr
	}
	if out == nil {
		return selectedEndpoint, nil
	}
	return selectedEndpoint, json.NewDecoder(resp.Body).Decode(out)
}

// KeyInfo serves the /v1/key passthrough: agents read their own key's budget
// (limits, per-window remaining, resets_at) through the attested endpoint they
// send inference to. The RAW BEARER NEVER LEAVES THE ENCLAVE — same contract
// as authorize: the control plane's /internal/gateway/key is keyed by the
// key's lookup hash + the internal gateway token. Returns the control-plane
// status + JSON body verbatim (the caller allowlists statuses).
func (c *Client) KeyInfo(ctx context.Context, bearer string) (int, []byte, error) {
	payload, err := json.Marshal(map[string]string{
		"api_key_lookup_hash": requestLookupHash(ctx, bearer),
	})
	if err != nil {
		return 0, nil, err
	}
	resp, err := c.postToFirstDialable(ctx, "/internal/gateway/key", payload)
	if err != nil {
		return 0, nil, err
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

type apiKeyLookupHashContextKey struct{}

// WithAPIKeyLookupHash returns an enclave-internal context that authorizes by
// an already-derived lookup hash. It exists for delayed batch execution so a
// raw API key never has to be persisted. Public HTTP requests cannot set Go
// context values, and callers must still pass through the normal authorize,
// reserve, settle, refund, and key-revocation checks.
func WithAPIKeyLookupHash(ctx context.Context, value string) (context.Context, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || len(value) != sha256.Size*2 {
		return nil, fmt.Errorf("trustedrouter: invalid API key lookup hash")
	}
	return context.WithValue(ctx, apiKeyLookupHashContextKey{}, value), nil
}

func requestLookupHash(ctx context.Context, bearer string) string {
	if ctx != nil {
		if value, ok := ctx.Value(apiKeyLookupHashContextKey{}).(string); ok && value != "" {
			return value
		}
	}
	return lookupHash(bearer)
}

// LookupHash returns the one-way lookup identifier used by the control plane.
// It is safe to persist as batch ownership metadata; raw API keys are never
// persisted, including in encrypted batch artifacts.
func LookupHash(raw string) string {
	return lookupHash(raw)
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

// publicModelsURL builds the versioned catalog URL from a control-plane base.
//
// THE BASE IS NOT VERSIONED, AND EVERY OTHER CALLER RELIES ON THAT. The
// internal endpoints are absolute from the domain root
// (/internal/gateway/authorize, /internal/gateway/settle, …), so GCP ships
// TR_CONTROL_PLANE_BASE_URL=https://trustedrouter.com and that is correct for
// them. PublicModels was the only method that assumed the base already carried
// /v1, so it fetched https://trustedrouter.com/models — the human-facing HTML
// page, which answers 200 with text/html. The status check passed, the JSON
// decode failed, and the enclave served 503 "model catalog unavailable" while
// inference was perfectly healthy.
//
// Normalising here rather than changing the deploy variable keeps the two
// conventions from silently disagreeing again: whichever form a cloud passes,
// this resolves to exactly one /v1/models.
func publicModelsURL(base string) string {
	return publicCatalogURL(base, "/v1/models")
}

func publicCatalogURL(base, path string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	trimmed = strings.TrimSuffix(trimmed, "/v1")
	return trimmed + "/" + strings.TrimLeft(path, "/")
}
