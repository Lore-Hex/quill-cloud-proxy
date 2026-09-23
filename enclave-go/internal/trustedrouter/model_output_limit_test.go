package trustedrouter

import "testing"

func TestCachedModelOutputLimit(t *testing.T) {
	for _, tt := range []struct {
		name, body, model string
		want              int
	}{
		{"unknown", `{"data":[{"id":"a","top_provider":{"max_completion_tokens":8192}}]}`, "b", 0},
		{"known", `{"data":[{"id":"a","top_provider":{"max_completion_tokens":8192}}]}`, "a", 8192},
		{"minimum", `{"data":[{"id":"a","max_output_tokens":4096,"top_provider":{"max_completion_tokens":8192}}]}`, "a", 4096},
		{"top provider minimum", `{"data":[{"id":"a","max_output_tokens":8192,"top_provider":{"max_completion_tokens":4096}}]}`, "a", 4096},
		{"unknown is not context length", `{"data":[{"id":"a","context_length":1048576,"top_provider":{"max_completion_tokens":null}}]}`, "a", 0},
		{"nonpositive", `{"data":[{"id":"a","max_output_tokens":-1,"top_provider":{"max_completion_tokens":0}}]}`, "a", 0},
		{"missing cache", ``, "a", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{modelsBody: []byte(tt.body)}
			if got := c.CachedModelOutputLimit(tt.model); got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
	var c *Client
	if c.CachedModelOutputLimit("a") != 0 {
		t.Fatal("nil client must mean unknown")
	}
}
