package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
	"github.com/aws/smithy-go"
)

func TestGatewayRedactsTruncatedEscapedCredentialsAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	const key = "provider-owned-secret"
	for _, route := range []string{"messages", "chat.completions", "responses"} {
		for _, stream := range []bool{false, true} {
			for _, escaped := range []string{
				`\u0070\u0072\u006f\u0076\u0069\u0064\u0065\u0072\u002d\u006f\u0077\u006e\u0065\u0064\u002d\u0073\u0065\u0063\u0072\u0065\u0074`,
				`pro\u0076ider-owned-\u0073ecret`,
			} {
				t.Run(fmt.Sprintf("%s/stream=%t/%s", route, stream, escaped), func(t *testing.T) {
					gateway, auth, options, refunds := errorTestGateway(t, false, false)
					provider := streamingProviderFunc(func(ctx context.Context, _ io.Writer, _ llm.InvokeOptions) error {
						upstreamerror.RecordCredential(ctx, key)
						body := `{"error":{"message":"rejected ` + escaped + `"},"padding":"` + strings.Repeat("x", 5000) + `"}`
						payload, err := io.ReadAll(io.LimitReader(strings.NewReader(body), 4096))
						if err != nil {
							return err
						}
						return &upstreamerror.Error{Status: 400, Body: string(payload)}
					})
					var out bytes.Buffer
					serveErrorTestRoute(t.Context(), route, stream, &out, provider, gateway, auth, options)
					response, err := http.ReadResponse(bufio.NewReader(&out), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					var body struct {
						Error struct {
							Message  string
							Metadata struct{ Raw string }
						}
					}
					if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					want := (`{"error":{"message":"rejected ***"},"padding":"` + strings.Repeat("x", 5000))[:1200]
					if response.StatusCode != 400 || *refunds != 1 || body.Error.Message != want || body.Error.Metadata.Raw != want {
						t.Fatalf("escaped secret reached client: status=%d refunds=%d body=%+v", response.StatusCode, *refunds, body)
					}
				})
			}
		}
	}
}

func TestGatewayRedactsCredentialPrefixesAtTruncatedBodyEnd(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	const key = "provider-owned-secret"
	for _, route := range []string{"messages", "chat.completions", "responses"} {
		for _, stream := range []bool{false, true} {
			for _, tc := range []struct{ name, body, want string }{
				{"credential cut by one character", `{"x-api-key":"provider-owned-secre`, `{"x-api-key":"***`},
				{"message cut mid credential", `{"error":{"message":"rejected provider-own`, `{"error":{"message":"rejected ***`},
				{"escaped credential field", `{"x-\u0061pi-key":"pro\u0076ider-owned-secre`, `{"x-api-key":"***`},
				{"escaped message prefix", `{"error":{"message":"rejected pro\u0076ider-\u006fwn`, `{"error":{"message":"rejected ***`},
				{"ordinary short prefix", `ordinary text about provide`, `ordinary text about provide`},
				{"dangling backslash", `{"error":{"message":"rejected provider-owned-secre\`, `{"error":{"message":"rejected ***`},
				{"unicode escape without digits", `{"error":{"message":"rejected provider-owned-secre\u`, `{"error":{"message":"rejected ***`},
				{"unicode escape with one digit", `{"error":{"message":"rejected provider-owned-secre\u0`, `{"error":{"message":"rejected ***`},
				{"unicode escape with two digits", `{"error":{"message":"rejected provider-owned-secre\u00`, `{"error":{"message":"rejected ***`},
				{"unicode escape with three digits", `{"error":{"message":"rejected provider-owned-secre\u007`, `{"error":{"message":"rejected ***`},
				{"unpaired high surrogate", `{"error":{"message":"rejected provider-owned-\ud83d`, `{"error":{"message":"rejected ***`},
				{"low surrogate dangling backslash", `{"error":{"message":"rejected provider-owned-\ud83d\`, `{"error":{"message":"rejected ***`},
				{"low surrogate without digits", `{"error":{"message":"rejected provider-owned-\ud83d\u`, `{"error":{"message":"rejected ***`},
				{"low surrogate with one digit", `{"error":{"message":"rejected provider-owned-\ud83d\ud`, `{"error":{"message":"rejected ***`},
				{"low surrogate with two digits", `{"error":{"message":"rejected provider-owned-\ud83d\udd`, `{"error":{"message":"rejected ***`},
				{"low surrogate with three digits", `{"error":{"message":"rejected provider-owned-\ud83d\udd1`, `{"error":{"message":"rejected ***`},
				{"complete trailing escape", `{"error":{"message":"ordinary\u0021`, `{"error":{"message":"ordinary!`},
			} {
				t.Run(fmt.Sprintf("%s/stream=%t/%s", route, stream, tc.name), func(t *testing.T) {
					gateway, auth, options, refunds := errorTestGateway(t, false, false)
					provider := streamingProviderFunc(func(ctx context.Context, _ io.Writer, _ llm.InvokeOptions) error {
						upstreamerror.RecordCredential(ctx, key)
						upstreamerror.RecordCredential(ctx, "provider-owned-🔐secret")
						return &upstreamerror.Error{Status: 400, Body: tc.body}
					})
					var out bytes.Buffer
					serveErrorTestRoute(t.Context(), route, stream, &out, provider, gateway, auth, options)
					response, err := http.ReadResponse(bufio.NewReader(&out), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					var body struct {
						Error struct {
							Message  string
							Metadata struct{ Raw string }
						}
					}
					if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != 400 || *refunds != 1 || body.Error.Message != tc.want || body.Error.Metadata.Raw != tc.want {
						t.Fatalf("truncated credential reached client: status=%d refunds=%d body=%+v want=%q", response.StatusCode, *refunds, body, tc.want)
					}
				})
			}
		}
	}
}

type bedrockStatusError struct{ code, message string }

func (e *bedrockStatusError) Error() string                 { return "Bedrock request failed" }
func (e *bedrockStatusError) HTTPStatusCode() int           { return 400 }
func (e *bedrockStatusError) ErrorCode() string             { return e.code }
func (e *bedrockStatusError) ErrorMessage() string          { return e.message }
func (e *bedrockStatusError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestStructuredProviderFailureDetailsAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, route := range []string{"messages", "chat.completions", "responses"} {
		for _, stream := range []bool{false, true} {
			for _, source := range []string{"bedrock", "bedrock redacted", "chutes"} {
				t.Run(fmt.Sprintf("%s/%s/stream=%t", source, route, stream), func(t *testing.T) {
					gateway, auth, options, refunds := errorTestGateway(t, false, false)
					message, code, status := "The provided model identifier is invalid.", "ValidationException", 400
					if source == "bedrock redacted" {
						message, code = "rejected provider-owned-secret Bearer hidden "+strings.Repeat("x", 1500), "ValidationException-sk-abcdef"
					}
					provider := streamingProviderFunc(func(ctx context.Context, _ io.Writer, _ llm.InvokeOptions) error {
						upstreamerror.RecordCredential(ctx, "provider-owned-secret")
						if source == "chutes" {
							// The authenticated decrypt/translate path and all three
							// adapters are covered in llm.TestChutesAuthenticatedPrettyJSONAcrossAPIs.
							return upstreamerror.CheckEvent("", "{\n\"error\":{\"code\":403,\"message\":\"denied\"}\n}")
						}
						return fmt.Errorf("invoke: %w", &bedrockStatusError{code: code, message: message})
					})
					var out bytes.Buffer
					serveErrorTestRoute(t.Context(), route, stream, &out, provider, gateway, auth, options)
					response, err := http.ReadResponse(bufio.NewReader(&out), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					var body struct {
						Error struct {
							Message  string
							Code     any
							Metadata struct{ Raw string }
						}
					}
					if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					var wantCode any = code
					if source == "chutes" {
						message, status, wantCode = "denied", 403, float64(403)
					}
					if source == "bedrock redacted" {
						message, wantCode = ("rejected *** Bearer *** " + strings.Repeat("x", 1500))[:1200], "ValidationException-sk-***"
					}
					if response.StatusCode != status || response.Header.Get("Content-Type") != "application/json" || *refunds != 1 || body.Error.Message != message || body.Error.Code != wantCode || len(body.Error.Metadata.Raw) > 1200 || strings.Contains(body.Error.Metadata.Raw, "provider-owned-secret") || strings.Contains(body.Error.Metadata.Raw, "hidden") {
						t.Fatalf("provider failure details/billing: status=%d refunds=%d body=%+v", response.StatusCode, *refunds, body)
					}
				})
			}
		}
	}
}
