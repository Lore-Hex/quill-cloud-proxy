package video

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type QueueResult struct {
	ProviderModel string
	QueueID       string
}

type PollState string

const (
	PollProcessing PollState = "processing"
	PollCompleted  PollState = "completed"
	PollFailed     PollState = "failed"
)

type PollResult struct {
	State          PollState
	ProviderStatus string
	Body           io.ReadCloser
	ContentType    string
	DownloadURL    string
}

type Provider interface {
	ID() string
	Enabled() bool
	Supports(*ResolvedRequest) bool
	QuoteResolved(context.Context, *ResolvedRequest) (int, error)
	QueueResolved(context.Context, *ResolvedRequest) (*QueueResult, error)
	Retrieve(context.Context, string, string) (*PollResult, error)
	Download(context.Context, string) (*PollResult, error)
	Complete(context.Context, string, string) error
}

// QueueTimeout lets upload-heavy provider adapters request a bounded timeout
// without making every provider implement another method.
func QueueTimeout(provider Provider) time.Duration {
	const fallback = 45 * time.Second
	type timeoutProvider interface {
		QueueTimeout() time.Duration
	}
	configured, ok := provider.(timeoutProvider)
	if !ok {
		return fallback
	}
	timeout := configured.QueueTimeout()
	if timeout < 5*time.Second || timeout > 5*time.Minute {
		return fallback
	}
	return timeout
}

type ProviderKeys struct {
	Venice     string
	Google     string
	MiniMax    string
	AtlasCloud string
	XAI        string
	Alibaba    string
	LTX        string
	Runway     string
	OpenAI     string
	Kling      string
	Decart     string
}

type Registry struct {
	providers map[string]Provider
}

func NewRegistry(keys ProviderKeys, httpc *http.Client) *Registry {
	return NewRegistryWithProviders(
		NewGoogleVeoClient(keys.Google, httpc),
		NewMiniMaxClient(keys.MiniMax, httpc),
		NewAtlasCloudVideoClient(keys.AtlasCloud, httpc),
		NewXAIClient(keys.XAI, httpc),
		NewAlibabaClient(keys.Alibaba, httpc),
		NewLTXClient(keys.LTX, httpc),
		NewRunwayClient(keys.Runway, httpc),
		NewOpenAIVideoClient(keys.OpenAI, httpc),
		NewKlingClient(keys.Kling, httpc),
		NewDecartVideoClient(keys.Decart, httpc),
		NewVeniceClient(keys.Venice, httpc),
	)
}

func NewRegistryWithProviders(providers ...Provider) *Registry {
	registry := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		if provider == nil || strings.TrimSpace(provider.ID()) == "" {
			continue
		}
		registry.providers[provider.ID()] = provider
	}
	return registry
}

func (r *Registry) Enabled() bool {
	if r == nil {
		return false
	}
	for _, provider := range r.providers {
		if provider.Enabled() {
			return true
		}
	}
	return false
}

func (r *Registry) Provider(id string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	provider, ok := r.providers[strings.TrimSpace(id)]
	return provider, ok && provider.Enabled()
}

func (r *Registry) Supporting(request *ResolvedRequest) []Provider {
	if r == nil || request == nil {
		return nil
	}
	providers := make([]Provider, 0, len(r.providers))
	for _, provider := range r.providers {
		if provider.Enabled() && provider.Supports(request) {
			providers = append(providers, provider)
		}
	}
	sort.SliceStable(providers, func(i, j int) bool {
		return providerRank(request.Model.ID, providers[i].ID()) < providerRank(request.Model.ID, providers[j].ID())
	})
	return providers
}

func providerRank(modelID, provider string) int {
	if direct := directProviderForModel(modelID); direct != "" && provider == direct {
		return 0
	}
	if provider == "venice" {
		return 100
	}
	return 50
}

func directProviderForModel(modelID string) string {
	switch modelID {
	case "google/veo-3.1", "google/veo-3.1-fast":
		return "google-ai-studio"
	case "minimax/hailuo-3":
		return "minimax"
	case "x-ai/grok-imagine-video":
		return "grok"
	case "alibaba/wan-2.7":
		return "alibaba"
	case "lightricks/ltx-2.3", "lightricks/ltx-2.3-fast":
		return "ltx"
	case "runway/gen-4.5":
		return "runway"
	case "openai/sora-2", "openai/sora-2-pro":
		return "openai"
	case "kling/v3-pro", "kling/o3-pro":
		return "kling"
	case "decart/lucy-2.5", "decart/lucy-vton-3.5", "decart/lucy-restyle-2":
		return "decart"
	default:
		return ""
	}
}

type HTTPError struct {
	Provider  string
	Status    int
	Retryable bool
}

// InputError marks a caller-controlled asset failure. It must never be
// attributed to a model provider or retried against another paid route.
type InputError struct{ Message string }

func (e *InputError) Error() string {
	if e == nil || strings.TrimSpace(e.Message) == "" {
		return "video input could not be fetched"
	}
	return e.Message
}

func (e *HTTPError) Error() string {
	provider := strings.TrimSpace(e.Provider)
	if provider == "" {
		provider = "video provider"
	}
	return fmt.Sprintf("%s http %d", provider, e.Status)
}

func requireProviderSuccess(provider string, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &HTTPError{
		Provider:  provider,
		Status:    resp.StatusCode,
		Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
	}
}

func IsRetryableProviderError(err error) bool {
	if err == nil {
		return false
	}
	var inputErr *InputError
	if AsInputError(err, &inputErr) {
		return false
	}
	var httpErr *HTTPError
	if AsHTTPError(err, &httpErr) {
		return httpErr.Retryable
	}
	// Transport failures happen before an HTTP status exists and are safe to
	// roll over because no provider job id was returned.
	return true
}

func AsInputError(err error, target **InputError) bool {
	for err != nil {
		if typed, ok := err.(*InputError); ok {
			*target = typed
			return true
		}
		type unwrapper interface{ Unwrap() error }
		wrapped, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}

// AsHTTPError is kept as a tiny wrapper so provider selection code does not
// need to import errors just to inspect retryability.
func AsHTTPError(err error, target **HTTPError) bool {
	for err != nil {
		if typed, ok := err.(*HTTPError); ok {
			*target = typed
			return true
		}
		type unwrapper interface{ Unwrap() error }
		wrapped, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}
