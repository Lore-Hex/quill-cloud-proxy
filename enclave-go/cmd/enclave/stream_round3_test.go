package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestMessagesSettledCostWithoutProviderUsage(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, native := range []bool{false, true} {
		name := "translated"
		if native {
			name = "native"
		}
		t.Run(name, func(t *testing.T) {
			auth := costReportingAuthorization()
			var settles, refunds atomic.Int32
			gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := `{"data":{"cost_microdollars":19,"disposition":"finalized"}}`
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					encoded, _ := json.Marshal(map[string]any{"data": auth})
					body = string(encoded)
				case "/internal/gateway/settle":
					settles.Add(1)
				case "/internal/gateway/refund":
					refunds.Add(1)
				default:
					t.Errorf("unexpected control request %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})})
			provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
				wire := ""
				if native {
					wire = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"provider-msg\"}}\n\n"
				}
				wire += "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
				_, err := io.WriteString(w, wire)
				return err
			}}
			var out bytes.Buffer
			serveErrorTestRoute(t.Context(), "messages", true, &out, provider, gateway, auth, nil)
			response, err := http.ReadResponse(bufio.NewReader(&out), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || settles.Load() != 1 || refunds.Load() != 0 {
				t.Fatalf("status=%d settles=%d refunds=%d body=%s", response.StatusCode, settles.Load(), refunds.Load(), body)
			}
			var usage map[string]any
			terminals := 0
			for _, line := range strings.Split(string(body), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var event map[string]any
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
					t.Fatal(err)
				}
				if event["type"] == "message_delta" {
					terminals++
					usage, _ = event["usage"].(map[string]any)
				}
			}
			if terminals != 1 || !bytes.HasSuffix(body, []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")) {
				t.Fatalf("invalid terminal framing: %s", body)
			}
			if usage["cost_microdollars"] != float64(19) || usage["total_cost_microdollars"] != float64(19) {
				t.Fatalf("settled cost missing: %s", body)
			}
		})
	}
}
