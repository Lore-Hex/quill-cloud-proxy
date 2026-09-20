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
	model := req.Model
	if upstream := strings.TrimSpace(option.UpstreamModel); upstream != "" {
		model = upstream
	}
	// Two hosts serve the same decision model with different wire shapes. The
	// caller sees neither: both are translated to decide.Answer and then held
	// to the same decide.Verify.
	if provider == typeSafeProvider {
		return invokeTypeSafeSystemOne(ctx, httpc, c.baseURL, c.apiKey, model, req)
	}
	wire := *req
	wire.Model = model
	raw, err := postDecideJSON(ctx, httpc, provider, c.baseURL+"/evaluate", c.apiKey, wire)
	if err != nil {
		return nil, err
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

func postDecideJSON(ctx context.Context, httpc *http.Client, provider, url, apiKey string, body any) ([]byte, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: marshal body: %w", provider, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
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
	return raw, nil
}

// typeSafeProvider is TypeSafe AI's own API (POST {base}/systemone): the model
// vendor directly, so the request crosses one third party instead of two.
const typeSafeProvider = "typesafe"

// TypeSafe names the yes/no primitive "noul" and returns its probability in a
// field of the same name. Everything else lines up with the public contract.
const typeSafeBoolean = "noul"

func invokeTypeSafeSystemOne(ctx context.Context, httpc *http.Client, baseURL, apiKey, model string, req *DecideRequest) (*DecideResponse, error) {
	questions := make(map[string]decide.Question, len(req.Questions))
	for name, question := range req.Questions {
		if question.Type == decide.TypeBoolean {
			question.Type = typeSafeBoolean
		}
		questions[name] = question
	}
	wire := DecideRequest{Model: model, State: req.State, Questions: questions}
	raw, err := postDecideJSON(ctx, httpc, typeSafeProvider, baseURL+"/systemone", apiKey, wire)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Answers map[string]struct {
			Type          string             `json:"type"`
			Noul          *float64           `json:"noul"`
			Choice        *string            `json:"choice"`
			Score         *float64           `json:"score"`
			Probabilities map[string]float64 `json:"probabilities"`
		} `json:"answers"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("llm/%s: decode systemone response: %w", typeSafeProvider, err)
	}
	// Translate names only. Whether the result honours the contract is for
	// decide.Verify to say, exactly as it does for every other backend; extra
	// vendor fields (confidence, legend) are not part of the public contract.
	answers := make(map[string]decide.Answer, len(parsed.Answers))
	for name, answer := range parsed.Answers {
		translated := decide.Answer{Type: answer.Type, Choice: answer.Choice, Score: answer.Score, Probabilities: answer.Probabilities}
		if answer.Type == typeSafeBoolean {
			translated = decide.Answer{Type: decide.TypeBoolean, Probability: answer.Noul}
		}
		answers[name] = translated
	}
	return &DecideResponse{Answers: answers, InputTokens: parsed.Usage.InputTokens, OutputTokens: parsed.Usage.OutputTokens}, nil
}
