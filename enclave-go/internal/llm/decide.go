package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

// DecideClient is implemented by gateway clients that can reach a HOSTED
// decision model (the vendor's POST {baseURL}/systemone, or a relay's POST
// {baseURL}/evaluate). Like EmbeddingClient it is kept
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

// maxDecideResponseBytes bounds the upstream body at twice the largest answer
// decide.Parse admits, leaving room for the envelope, usage, and a host that
// pretty-prints. The two are tied so a request that was accepted can never be
// one whose correct answer is then discarded as oversized -- after the vendor
// has been paid for it.
const maxDecideResponseBytes = 2 * decide.MaxAnswerBytes

// DecideError is the ONLY error InvokeDecide returns, and it is content-free by
// construction: a class from a closed vocabulary, the provider, and for an HTTP
// failure the status. It never holds an upstream body or a decoder message.
// Both can echo the caller's state (a vendor 422 quotes the request; a decode
// error quotes the offending literal), and this enclave does not write request
// content to a log. There is nothing here to redact because nothing was kept.
type DecideError struct {
	Provider string
	Class    string
	Status   int // upstream HTTP status; 0 when the failure was not an HTTP response
}

// DecideError classes.
const (
	DecideErrConfig    = "config"          // no key, base URL or transport for this provider
	DecideErrCanceled  = "canceled"        // our context was cancelled
	DecideErrDeadline  = "deadline"        // our context timed out
	DecideErrTransport = "transport"       // the request never got an HTTP response
	DecideErrHTTP      = "http_status"     // a response that was not 200; see Status
	DecideErrTooLarge  = "response_size"   // body above maxDecideResponseBytes
	DecideErrDecode    = "response_decode" // body is not the documented JSON
	DecideErrDuplicate = "duplicate_key"   // body repeats a JSON key
)

func (e *DecideError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("llm/%s: decide %s %d", e.Provider, e.Class, e.Status)
	}
	return fmt.Sprintf("llm/%s: decide %s", e.Provider, e.Class)
}

// DecideErrorClass is the loggable description of an InvokeDecide failure. A
// foreign error is "unknown": its text is never returned, because nothing is
// known about what it holds.
func DecideErrorClass(err error) string {
	var failed *DecideError
	if !errors.As(err, &failed) {
		return "unknown"
	}
	if failed.Status != 0 {
		return fmt.Sprintf("%s_%d", failed.Class, failed.Status)
	}
	return failed.Class
}

// DecideErrorStatus is the upstream HTTP status behind err, if there was one.
func DecideErrorStatus(err error) (int, bool) {
	var failed *DecideError
	if errors.As(err, &failed) && failed.Status != 0 {
		return failed.Status, true
	}
	return 0, false
}

func decideTransportError(ctx context.Context, provider string, err error) *DecideError {
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return &DecideError{Provider: provider, Class: DecideErrCanceled}
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return &DecideError{Provider: provider, Class: DecideErrDeadline}
	}
	return &DecideError{Provider: provider, Class: DecideErrTransport}
}

// decodeDecideBody unmarshals an upstream body that has already been checked
// for repeated keys, returning content-free errors for both failures.
func decodeDecideBody(provider string, raw []byte, into any) error {
	if err := decide.CheckNoDuplicateKeys(raw); err != nil {
		if decide.ViolationKind(err) == decide.KindDuplicate {
			return &DecideError{Provider: provider, Class: DecideErrDuplicate}
		}
		return &DecideError{Provider: provider, Class: DecideErrDecode}
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return &DecideError{Provider: provider, Class: DecideErrDecode}
	}
	return nil
}

func (c *openAICompatibleClient) InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error) {
	option := firstOptions(options)
	provider := c.provider
	if option.Provider != "" {
		provider = normalizeDirectProvider(option.Provider)
	}
	if strings.TrimSpace(c.apiKey) == "" || strings.TrimSpace(c.baseURL) == "" {
		return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
	}
	httpc, err := c.resolveHTTPClient()
	if err != nil {
		return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
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
	if err := decodeDecideBody(provider, raw, &parsed); err != nil {
		return nil, err
	}
	return &DecideResponse{Answers: parsed.Answers, InputTokens: parsed.Usage.InputTokens, OutputTokens: parsed.Usage.OutputTokens}, nil
}

func postDecideJSON(ctx context.Context, httpc *http.Client, provider, url, apiKey string, body any) ([]byte, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return nil, decideTransportError(ctx, provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body is drained for connection reuse and then DROPPED. A vendor
		// 4xx quotes the request it rejected, so the status is all we keep.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, &DecideError{Provider: provider, Class: DecideErrHTTP, Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDecideResponseBytes+1))
	if err != nil {
		return nil, decideTransportError(ctx, provider, err)
	}
	if len(raw) > maxDecideResponseBytes {
		return nil, &DecideError{Provider: provider, Class: DecideErrTooLarge}
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
	if err := decodeDecideBody(typeSafeProvider, raw, &parsed); err != nil {
		return nil, err
	}
	// Translate NAMES only, and carry every answer field across. Whether the
	// result honours the contract is for decide.Verify to say, exactly as it
	// does for every other backend -- which it can only do if it sees what the
	// vendor sent. Dropping choice/score/probabilities from a "noul" answer
	// here would turn a self-contradictory answer into a clean boolean. Vendor
	// metadata (confidence, legend) is not part of the public contract.
	answers := make(map[string]decide.Answer, len(parsed.Answers))
	for name, answer := range parsed.Answers {
		translated := decide.Answer{Type: answer.Type, Probability: answer.Noul, Choice: answer.Choice, Score: answer.Score, Probabilities: answer.Probabilities}
		if answer.Type == typeSafeBoolean {
			translated.Type = decide.TypeBoolean
		}
		answers[name] = translated
	}
	return &DecideResponse{Answers: answers, InputTokens: parsed.Usage.InputTokens, OutputTokens: parsed.Usage.OutputTokens}, nil
}
