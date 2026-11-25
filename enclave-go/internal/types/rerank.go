package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// RerankRequest retains the same attribution and routing metadata as embeddings.
type RerankRequest struct {
	EmbeddingRequest
	Query           string
	Documents       []string
	TopN            int
	ReturnDocuments bool
}

type RerankValidationError struct{ Param, Message string }

func (e *RerankValidationError) Error() string { return e.Message }

func ParseRerankRequest(raw []byte) (*RerankRequest, error) {
	r := &RerankRequest{ReturnDocuments: true}
	if err := json.Unmarshal(raw, &r.EmbeddingRequest); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	invalid := func(param, message string) (*RerankRequest, error) {
		return nil, &RerankValidationError{param, message}
	}
	if r.Model == "" {
		return invalid("model", "model is required")
	}
	if err := json.Unmarshal(fields["query"], &r.Query); err != nil || r.Query == "" {
		return invalid("query", "query must be a non-empty string")
	}
	var documents []json.RawMessage
	if err := json.Unmarshal(fields["documents"], &documents); err != nil || len(documents) < 1 || len(documents) > 1000 {
		return invalid("documents", "documents must contain 1 to 1000 text items")
	}
	for i, raw := range documents {
		var text string
		param := fmt.Sprintf("documents[%d]", i)
		if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &text) == nil {
			r.Documents = append(r.Documents, text)
			continue
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return invalid(param, "each document must be a string or an object with string text")
		}
		if _, ok := object["image"]; ok {
			return invalid(param+".image", "image documents are not supported")
		}
		value, ok := object["text"]
		if !ok || len(object) != 1 || bytes.Equal(value, []byte("null")) || json.Unmarshal(value, &text) != nil {
			return invalid(param, "each document object must contain only string text")
		}
		r.Documents = append(r.Documents, text)
	}
	r.TopN = len(r.Documents)
	if raw, ok := fields["top_n"]; ok {
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &r.TopN) != nil || r.TopN <= 0 {
			return invalid("top_n", "top_n must be a positive integer")
		}
		if r.TopN > len(r.Documents) {
			r.TopN = len(r.Documents)
		}
	}
	if raw, ok := fields["return_documents"]; ok {
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &r.ReturnDocuments) != nil {
			return invalid("return_documents", "return_documents must be a boolean")
		}
	}
	// Input is not part of rerank and must not be retained as metadata.
	r.Input = nil
	return r, nil
}

// EstimateRerankInputTokens repeats the query for every document. Voyage defines
// total tokens this way; for Cohere this is the larger reading of pair counting.
func EstimateRerankInputTokens(query string, documents []string) int {
	return EstimateEmbeddingInputTokens([]string{query})*len(documents) + EstimateEmbeddingInputTokens(documents)
}

type RerankDocument struct {
	Text string `json:"text"`
}
type RerankResult struct {
	Index          int             `json:"index"`
	RelevanceScore float64         `json:"relevance_score"`
	Document       *RerankDocument `json:"document,omitempty"`
}
type RerankResponse struct {
	Results     []RerankResult
	InputTokens *int
	SearchUnits *int
}

// PublicRerankResults validates before sorting and reconstructs documents only
// from the request. Provider document echoes are never used.
func PublicRerankResults(req *RerankRequest, rows []RerankResult) ([]RerankResult, error) {
	if len(rows) > len(req.Documents) {
		return nil, fmt.Errorf("invalid rerank result count")
	}
	seen := make(map[int]bool, len(rows))
	out := make([]RerankResult, 0, len(rows))
	for _, row := range rows {
		if row.Index < 0 || row.Index >= len(req.Documents) || seen[row.Index] || math.IsNaN(row.RelevanceScore) || math.IsInf(row.RelevanceScore, 0) {
			return nil, fmt.Errorf("invalid rerank result")
		}
		seen[row.Index] = true
		row.Document = nil
		if req.ReturnDocuments {
			row.Document = &RerankDocument{Text: req.Documents[row.Index]}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RelevanceScore == out[j].RelevanceScore {
			return out[i].Index < out[j].Index
		}
		return out[i].RelevanceScore > out[j].RelevanceScore
	})
	if req.TopN > 0 && len(out) > req.TopN {
		out = out[:req.TopN]
	}
	return out, nil
}
