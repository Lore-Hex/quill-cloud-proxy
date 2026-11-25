package types

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestRerankValidation(t *testing.T) {
	for _, tc := range []struct{ name, patch, param string }{
		{"missing_model", `{"query":"q","documents":["d"]}`, "model"},
		{"empty_query", `{"query":""}`, "query"},
		{"query_number", `{"query":4}`, "query"},
		{"query_null", `{"query":null}`, "query"},
		{"missing_documents", `{"documents":null}`, "documents"},
		{"empty_documents", `{"documents":[]}`, "documents"},
		{"scalar_documents", `{"documents":"d"}`, "documents"},
		{"number", `{"documents":[3]}`, "documents[0]"},
		{"null", `{"documents":[null]}`, "documents[0]"},
		{"array", `{"documents":[[]]}`, "documents[0]"},
		{"no_text", `{"documents":[{}]}`, "documents[0]"},
		{"text_number", `{"documents":[{"text":5}]}`, "documents[0]"},
		{"text_null", `{"documents":[{"text":null}]}`, "documents[0]"},
		{"image", `{"documents":[{"text":"d","image":null}]}`, "documents[0].image"},
		{"extra_document_member", `{"documents":[{"text":"d","extra":1}]}`, "documents[0]"},
		{"zero_top", `{"top_n":0}`, "top_n"},
		{"negative_top", `{"top_n":-1}`, "top_n"},
		{"fraction_top", `{"top_n":1.5}`, "top_n"},
		{"string_top", `{"top_n":"1"}`, "top_n"},
		{"null_top", `{"top_n":null}`, "top_n"},
		{"null_return", `{"return_documents":null}`, "return_documents"},
		{"string_return", `{"return_documents":"true"}`, "return_documents"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := map[string]any{"model": "voyage/rerank-3", "query": "q", "documents": []string{"d"}}
			if tc.name == "missing_model" {
				delete(base, "model")
			}
			var patch map[string]any
			_ = json.Unmarshal([]byte(tc.patch), &patch)
			for k, v := range patch {
				base[k] = v
			}
			raw, _ := json.Marshal(base)
			_, err := ParseRerankRequest(raw)
			validation, ok := err.(*RerankValidationError)
			if !ok || validation.Param != tc.param {
				t.Fatalf("error=%v want param=%s", err, tc.param)
			}
		})
	}
	for _, n := range []int{1, 1000, 1001} {
		docs := make([]string, n)
		raw, _ := json.Marshal(map[string]any{"model": "m", "query": "q", "documents": docs})
		_, err := ParseRerankRequest(raw)
		if (err == nil) != (n <= 1000) {
			t.Fatalf("count=%d error=%v", n, err)
		}
	}
	req, err := ParseRerankRequest([]byte(`{"model":"m","query":"q","documents":["",{"text":"d"}],"top_n":99,"unknown":true,"session_id":"session","user":"user","provider":{"only":["voyage"]}}`))
	if err != nil || req.TopN != 2 || !req.ReturnDocuments || req.Documents[0] != "" || req.SessionID != "session" || req.User != "user" || req.Provider.Only[0] != "voyage" {
		t.Fatal("valid request was not preserved")
	}
}

func TestRerankEstimate(t *testing.T) {
	for _, provider := range []string{"voyage", "cohere"} {
		t.Run(provider, func(t *testing.T) {
			for _, tc := range []struct {
				query string
				docs  []string
				want  int
			}{
				{"", []string{""}, 2}, {"12345678", []string{"12345678", "1234"}, 7}, {"q", []string{"", "abc", "界"}, 6},
			} {
				if got := EstimateRerankInputTokens(tc.query, tc.docs); got != tc.want {
					t.Fatalf("tokens=%d want=%d", got, tc.want)
				}
			}
		})
	}
}

func TestRerankPublicResults(t *testing.T) {
	req := &RerankRequest{Documents: []string{"a", "b", "c"}, TopN: 2, ReturnDocuments: true}
	rows := []RerankResult{{Index: 2, RelevanceScore: 0.8}, {Index: 1, RelevanceScore: 0.9}, {Index: 0, RelevanceScore: 0.9, Document: &RerankDocument{Text: "provider text"}}}
	out, err := PublicRerankResults(req, rows)
	if err != nil || len(out) != 2 || out[0].Index != 0 || out[1].Index != 1 || out[0].Document.Text != "a" {
		t.Fatal("sort or document reconstruction failed")
	}
	req.ReturnDocuments = false
	out, err = PublicRerankResults(req, rows)
	raw, _ := json.Marshal(out)
	if err != nil || strings.Contains(string(raw), "document") {
		t.Fatal("document omission failed")
	}
	for _, bad := range [][]RerankResult{
		{{Index: -1}}, {{Index: 3}}, {{Index: 0}, {Index: 0}}, {{Index: 0, RelevanceScore: math.NaN()}}, {{Index: 0, RelevanceScore: math.Inf(1)}}, {{Index: 0}, {Index: 1}, {Index: 2}, {Index: 3}},
	} {
		if _, err := PublicRerankResults(req, bad); err == nil {
			t.Fatal("invalid result accepted")
		}
	}
}
