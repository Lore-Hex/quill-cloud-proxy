package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func system1TestImage(t *testing.T) string {
	t.Helper()
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 128, 128))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data.Bytes())
}

func TestSystem1DecisionLimitsBeforeInference(t *testing.T) {
	for _, model := range []string{"system1models/s1-fast", "system1models-eu/s1-fast"} {
		for _, change := range []string{"two_questions", "oversized_state", "image_on_text", "remote_image", "bad_image", "two_images"} {
			t.Run(model+"/"+change, func(t *testing.T) {
				body := map[string]any{"model": model, "state": "red", "questions": map[string]any{"q": map[string]any{"type": "boolean", "instructions": "Red?"}}}
				switch change {
				case "two_questions":
					body["questions"].(map[string]any)["r"] = body["questions"].(map[string]any)["q"]
				case "oversized_state":
					body["state"] = strings.Repeat("x", 16384)
				case "image_on_text":
					body["images"] = []string{"data:image/png;base64,eA=="}
				case "remote_image":
					body["model"] = strings.Replace(model, "s1-fast", "s1-vision", 1)
					body["images"] = []string{"https://example.com/x.png"}
				case "bad_image":
					body["model"] = strings.Replace(model, "s1-fast", "s1-vision", 1)
					body["images"] = []string{"data:image/png;base64,eA=="}
				case "two_images":
					body["model"] = strings.Replace(model, "s1-fast", "s1-vision", 1)
					body["images"] = []string{"a", "b"}
				}
				raw, _ := json.Marshal(body)
				client := &fakeDecider{}
				status, _ := runDecide(t, client, string(raw))
				if status != 400 || client.seen != nil {
					t.Fatalf("invalid input reached inference: status=%d", status)
				}
			})
		}
	}
}

func TestSystem1SettlementUsesReportedInputExactlyOnce(t *testing.T) {
	imageURL := system1TestImage(t)
	for _, slug := range []string{"system1models", "system1models-eu"} {
		for _, fail := range []bool{false, true} {
			model := slug + "/s1-vision"
			endpoint := model + "@" + slug + "/prepaid"
			authorizations, settlements, refunds := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if strings.Contains(string(raw), "PRIVATE-STATE") {
					t.Error("prompt leaked to control plane")
				}
				var body map[string]any
				_ = json.Unmarshal(raw, &body)
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authorizations++
					_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"a","workspace_id":"w","api_key_hash":"k","model":%q,"endpoint_id":%q,"provider":%q,"upstream_model":"s1-vision","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`, model, endpoint, slug)
				case "/internal/gateway/settle":
					settlements++
					if body["actual_input_tokens"] != float64(4444) || body["actual_output_tokens"] != float64(0) || body["selected_endpoint"] != endpoint {
						t.Errorf("incorrect settlement: %#v", body)
					}
					_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"g","cost_microdollars":20}}`)
				case "/internal/gateway/refund":
					refunds++
					_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
				default:
					t.Errorf("unexpected control-plane path: %s", r.URL.Path)
				}
			}))
			probability := 0.9
			backend := &cancellingDecider{tokens: 4444, answers: map[string]decide.Answer{"q": {Type: decide.TypeBoolean, Probability: &probability}}}
			if fail {
				backend.answers = nil
			}
			status, _ := rawDecide(context.Background(), backend, trustedrouter.New(server.URL, "test", server.Client()), `{"model":"`+model+`","state":"PRIVATE-STATE","images":["`+imageURL+`"],"questions":{"q":{"type":"noul","instructions":"Red?"}}}`)
			server.Close()
			if authorizations != 1 || settlements+refunds != 1 || (!fail && (status != 200 || settlements != 1)) || (fail && (status != 502 || refunds != 1)) {
				t.Fatalf("status=%d authorize=%d settle=%d refund=%d", status, authorizations, settlements, refunds)
			}
		}
	}
}

func TestSystem1UsesVerifiedHostedPath(t *testing.T) {
	probability := 0.9
	for _, model := range []string{"system1models/s1-fast", "system1models-eu/s1-pro", "system1models/s1-future"} {
		client := &fakeDecider{answers: map[string]decide.Answer{"q": {Type: decide.TypeBoolean, Probability: &probability}}}
		status, _ := runDecide(t, client, `{"model":"`+model+`","state":"red","questions":{"q":{"type":"noul","instructions":"Red?"}}}`)
		if status != 200 || client.seen == nil {
			t.Fatalf("hosted path not selected for %s: %d", model, status)
		}
	}
}
