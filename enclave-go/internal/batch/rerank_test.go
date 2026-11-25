package batch

import "testing"

func TestRerankBatchUnsupported(t *testing.T) {
	_, err := ParseCreate([]byte(`{"endpoint":"/v1/rerank","model":"voyage/rerank-3","requests":[{"custom_id":"one","body":{"query":"q","documents":["d"]}}]}`))
	if err == nil || err.Status != 400 {
		t.Fatal("rerank must remain outside batch")
	}
}
