package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

// DecideClient is implemented by gateway clients that can reach a HOSTED
// decision model (POST {baseURL}/evaluate). Like EmbeddingClient it is kept
// off the Client interface so single-backend builds need not implement it; the
// route does a runtime type assertion and 501s otherwise.
type DecideClient interface {
	InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error)
}

// DecideRequest is the upstream wire body. Questions are re-marshalled from
// the validated form, never forwarded as raw caller bytes.
type DecideRequest struct {
	Model     string                     `json:"model"`
	State     json.RawMessage            `json:"state"`
	Questions map[string]decide.Question `json:"questions"`
}

// DecideResponse is the upstream result BEFORE verification. The caller must
// run decide.Verify on Answers; nothing here is trusted.
type DecideResponse struct {
	Answers      map[string]decide.Answer
	InputTokens  int
	OutputTokens int
}

// maxDecideResponseBytes bounds the upstream body: 64 questions x 255 options
// of short numeric entries fits comfortably; anything larger is not a decision.
const maxDecideResponseBytes = 4 << 20

func (c *openAICompatibleClient) InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error) {
	option := firstOptions(options)
	provider := c.provider
	if option.Provider != "" {
		provider = normalizeDirectProvider(option.Provider)
	}
	if strings.TrimSpace(c.apiKey) == "" {
		return nil, fmt.Errorf("llm/%s: missing api key", provider)
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, fmt.Errorf("llm/%s: missing base URL", provider)
	}
	httpc, err := c.resolveHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("llm/%s: http client unavailable: %w", provider, err)
	}
	wire := *req
	if upstream := strings.TrimSpace(option.UpstreamModel); upstream != "" {
		wire.Model = upstream
	}
	bodyBytes, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: marshal body: %w", provider, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/evaluate", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: invoke: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDecideResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("llm/%s: read decide response: %w", provider, err)
	}
	if len(raw) > maxDecideResponseBytes {
		return nil, fmt.Errorf("llm/%s: decide response exceeds %d bytes", provider, maxDecideResponseBytes)
	}
	var parsed struct {
		Answers map[string]decide.Answer `json:"answers"`
		Usage   struct {
			InputTokens  int `json:"inputTokens"`
			OutputTokens int `json:"outputTokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("llm/%s: decode decide response: %w", provider, err)
	}
	return &DecideResponse{Answers: parsed.Answers, InputTokens: parsed.Usage.InputTokens, OutputTokens: parsed.Usage.OutputTokens}, nil
}
