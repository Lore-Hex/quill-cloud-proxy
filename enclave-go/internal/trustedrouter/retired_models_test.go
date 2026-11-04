package trustedrouter

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRetiredModelsNeverContactControlPlane(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("retired request contacted control plane: %s", r.URL.Path)
		w.WriteHeader(500)
	}))
	defer server.Close()
	client := New(server.URL, "internal", server.Client())
	for _, model := range []string{"tr-custom-model/demo", "tr-user-model/demo", "trustedrouter/user-demo", "nyte/user-demo", " TR-USER-MODEL/demo "} {
		for _, fallback := range []bool{false, true} {
			req := &qtypes.OpenAIChatRequest{Model: model, IdempotencyKey: "old-replay-key"}
			if fallback {
				req.Model, req.Models = "openai/gpt-4.1", []string{model}
			}
			auth, err := client.Authorize(t.Context(), "sk-test", req)
			var rejected *ControlPlaneError
			if auth != nil || !errors.As(err, &rejected) || rejected.StatusCode != 410 {
				t.Fatalf("retired request accepted: model=%q fallback=%t auth=%v err=%v", model, fallback, auth, err)
			}
		}
		auth, err := client.AuthorizeEmbeddings(t.Context(), "sk-test", &qtypes.EmbeddingRequest{Model: model}, 1)
		var rejected *ControlPlaneError
		if auth != nil || !errors.As(err, &rejected) || rejected.StatusCode != 410 {
			t.Fatalf("retired embeddings accepted: auth=%v err=%v", auth, err)
		}
	}
}

func TestRetiredAuthorizationRefundsWithoutDispatchOnEveryHostname(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		for _, kind := range []string{"user_provided", "prompt_wrapper", "", "unknown"} {
			t.Run(fmt.Sprint(confidential)+kind, func(t *testing.T) {
				var paths []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					paths = append(paths, r.URL.Path)
					if r.URL.Path == "/internal/gateway/refund" {
						_, _ = io.WriteString(w, `{"data":{"status":"refunded"}}`)
						return
					}
					_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_1","custom_model":{"kind":%q}}}`, kind)
				}))
				defer server.Close()
				client := New(server.URL, "internal", server.Client())
				ctx := t.Context()
				if confidential {
					ctx = WithConfidentialOnly(ctx)
				}
				auth, err := client.Authorize(ctx, "sk-test", &qtypes.OpenAIChatRequest{
					Model: "openai/gpt-4.1", Provider: &qtypes.ProviderRouting{MinPrivacy: "confidential"},
				})
				if auth != nil || err == nil {
					t.Fatalf("retired contract accepted: auth=%v err=%v", auth, err)
				}
				if len(paths) != 2 || paths[0] != "/internal/gateway/authorize" || paths[1] != "/internal/gateway/refund" {
					t.Fatalf("unexpected authorization must refund exactly once: %v", paths)
				}
			})
		}
	}
}
