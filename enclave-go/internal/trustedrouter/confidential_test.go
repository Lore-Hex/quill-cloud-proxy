package trustedrouter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestConfidentialUserHostedResolveHasNoHoldAndUnexpectedAuthorizeRefunds(t *testing.T) {
	for _, resolve := range []bool{true, false} {
		t.Run(map[bool]string{true: "resolve", false: "authorize"}[resolve], func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if r.URL.Path == "/internal/gateway/refund" {
					_, _ = io.WriteString(w, `{"data":{"status":"refunded"}}`)
					return
				}
				_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_1","custom_model":{"kind":"user_provided"}}}`)
			}))
			defer server.Close()
			client := New(server.URL, "internal", server.Client())
			ctx := WithConfidentialOnly(t.Context())
			var auth *Authorization
			var err error
			if resolve {
				auth, err = client.ResolveCustomModel(ctx, "sk-test", "trustedrouter/user-demo", "responses")
			} else {
				auth, err = client.Authorize(ctx, "sk-test", &qtypes.OpenAIChatRequest{
					Model: "trustedrouter/user-demo", Provider: &qtypes.ProviderRouting{MinPrivacy: "confidential"},
				})
			}
			if auth != nil || err == nil {
				t.Fatalf("user-hosted endpoint accepted: auth=%v err=%v", auth, err)
			}
			if resolve {
				if len(paths) != 1 || paths[0] != "/internal/gateway/resolve-custom-model" {
					t.Fatalf("resolve created a hold or refund: %v", paths)
				}
			} else if len(paths) != 2 || paths[0] != "/internal/gateway/authorize" || paths[1] != "/internal/gateway/refund" {
				t.Fatalf("unexpected authorization must refund exactly once: %v", paths)
			}
		})
	}
}

func TestConfidentialRejectsUserHostedButNotPromptWrapper(t *testing.T) {
	ctx := WithConfidentialOnly(context.Background())
	for _, kind := range []string{"user_provided", " USER_PROVIDED "} {
		auth := &Authorization{CustomModel: &CustomModel{Kind: kind}}
		if validateConfidentialAuthorization(ctx, auth) == nil {
			t.Fatal("user-hosted model accepted")
		}
		if validateConfidentialAuthorization(context.Background(), auth) != nil {
			t.Fatal("ordinary routing changed")
		}
	}
	if err := validateConfidentialAuthorization(ctx, &Authorization{CustomModel: &CustomModel{Kind: "prompt_wrapper"}}); err != nil {
		t.Fatal(err)
	}
}

func TestConfidentialNeverUsesLocalSpendLeaseAdmission(t *testing.T) {
	ctx := WithConfidentialOnly(context.Background())
	client := &Client{}
	valid := &qtypes.OpenAIChatRequest{Provider: &qtypes.ProviderRouting{MinPrivacy: "confidential"}}
	if plan, err := client.PrepareSpendLeaseAdmission(ctx, "", valid, "chat.completions", time.Now()); plan != nil || err != nil {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	if _, err := client.PrepareSpendLeaseAdmission(ctx, "", &qtypes.OpenAIChatRequest{}, "chat.completions", time.Now()); err == nil {
		t.Fatal("lost policy not rejected")
	}
}
