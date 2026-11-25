package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type RerankClient interface {
	InvokeRerank(context.Context, *qtypes.RerankRequest, ...InvokeOptions) (*qtypes.RerankResponse, error)
}

var ErrRerankUnsupported = errors.New("rerank not supported by this provider")
var ErrRerankInputLimit = errors.New("rerank input is too large; reduce query or document sizes")

// Embeddings use the shared HTTP timeout and a 4096-byte error-body limit.
// Rerank additionally bounds successful responses because it never needs vectors.
const maxRerankResponseBytes = 10 << 20

func invokeRerank(ctx context.Context, httpc *http.Client, provider, baseURL, apiKey string, req *qtypes.RerankRequest, option InvokeOptions) (*qtypes.RerankResponse, error) {
	if provider != "voyage" && provider != "cohere" {
		return nil, ErrRerankUnsupported
	}
	if option.ProviderAPIKey != "" || strings.EqualFold(option.UsageType, "BYOK") {
		return nil, errors.New("rerank requires Credits")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("rerank provider key unavailable")
	}
	if option.UpstreamModel == "" {
		return nil, errors.New("rerank upstream model unavailable")
	}
	payload := map[string]any{"model": option.UpstreamModel, "query": req.Query, "documents": req.Documents}
	// Fetch all ranks so a top_n boundary can be resolved by index on tied scores.
	if provider == "voyage" {
		payload["return_documents"] = false
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("rerank request encoding failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/rerank", bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("rerank request creation failed")
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "TrustedRouter/1.0")
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(request)
	if err != nil {
		return nil, errors.New("rerank provider request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusRequestEntityTooLarge {
			return nil, ErrRerankInputLimit
		}
		// Keep status classification without retaining provider text in the error.
		return nil, &upstreamHTTPError{status: resp.StatusCode, body: "rerank provider error"}
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxRerankResponseBytes+1))
	if err != nil || len(raw) > maxRerankResponseBytes {
		return nil, errors.New("invalid rerank provider response")
	}
	return parseRerankResponse(provider, raw, len(req.Documents))
}

func parseRerankResponse(provider string, raw []byte, count int) (*qtypes.RerankResponse, error) {
	invalid := errors.New("invalid rerank provider response")
	type row struct {
		Index *int     `json:"index"`
		Score *float64 `json:"relevance_score"`
	}
	var wire struct {
		Data    *[]row `json:"data"`
		Results *[]row `json:"results"`
		Usage   struct {
			Total *float64 `json:"total_tokens"`
		} `json:"usage"`
		Meta struct {
			Billed struct {
				Input  *float64 `json:"input_tokens"`
				Search *float64 `json:"search_units"`
			} `json:"billed_units"`
		} `json:"meta"`
	}
	if json.Unmarshal(raw, &wire) != nil {
		return nil, invalid
	}
	rows, tokens := wire.Data, wire.Usage.Total
	var search *float64
	if provider == "cohere" {
		rows, tokens, search = wire.Results, wire.Meta.Billed.Input, wire.Meta.Billed.Search
	} else if provider != "voyage" {
		return nil, ErrRerankUnsupported
	}
	if rows == nil || len(*rows) > count {
		return nil, invalid
	}
	toInt := func(v *float64) (*int, bool) {
		if v == nil {
			return nil, true
		}
		if *v < 0 || math.IsInf(*v, 0) || math.IsNaN(*v) || *v >= float64(math.MaxInt) || math.Trunc(*v) != *v {
			return nil, false
		}
		n := int(*v)
		return &n, true
	}
	input, ok := toInt(tokens)
	if !ok {
		return nil, invalid
	}
	units, ok := toInt(search)
	if !ok {
		return nil, invalid
	}
	result := &qtypes.RerankResponse{Results: make([]qtypes.RerankResult, 0, len(*rows)), InputTokens: input, SearchUnits: units}
	seen := make(map[int]bool, len(*rows))
	for _, r := range *rows {
		if r.Index == nil || r.Score == nil || *r.Index < 0 || *r.Index >= count || seen[*r.Index] || math.IsNaN(*r.Score) || math.IsInf(*r.Score, 0) {
			return nil, invalid
		}
		seen[*r.Index] = true
		result.Results = append(result.Results, qtypes.RerankResult{Index: *r.Index, RelevanceScore: *r.Score})
	}
	return result, nil
}
