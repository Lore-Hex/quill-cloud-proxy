//go:build llm_multi

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// By default the rejection is injected; the optional stale-manifest mode uses
// the real PrivateMode adapter too. Tinfoil always uses the real attestation
// sidecar and TLS-pinned adapter. Neither mode disrupts production routing.
func TestLivePrivatemodeRejectionToAttestedTinfoil(t *testing.T) {
	if os.Getenv("TR_LIVE_CONFIDENTIAL_FALLBACK") != "1" {
		t.Skip("opt-in paid test; requires real attestation sidecar and TINFOIL_API_KEY")
	}
	key := strings.TrimSpace(os.Getenv("TINFOIL_API_KEY"))
	if key == "" || os.Getenv("TINFOIL_ATTEST_SOCKET") == "" {
		t.Fatal("explicit key and isolated attestation socket required")
	}
	if os.Getenv("TR_LIVE_START_SIDECAR") == "1" {
		child := exec.CommandContext(t.Context(), "/attest-sidecar", "-socket", os.Getenv("TINFOIL_ATTEST_SOCKET"))
		child.Env = []string{"PATH=/usr/bin:/bin"}
		child.Stdout, child.Stderr = os.Stderr, os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		llm.SetExpectedSidecarPID(child.Process.Pid)
		t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait(); llm.SetExpectedSidecarPID(0) })
		deadline := time.Now().Add(time.Minute)
		for {
			if _, err := llm.TinfoilAttestedHTTPClient(); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("real attestation sidecar did not become ready")
			}
			time.Sleep(time.Second)
		}
	}
	// Real-rejection qualification compiles this test with a Go overlay mapping
	// the embedded manifest to the previously approved (now stale) v1.63 pin.
	// The production pin and production services are never modified for this.
	realRejection := os.Getenv("TR_LIVE_PRIVATEMODE_REJECTION") == "1"
	privateKey := "synthetic-never-sent"
	if realRejection {
		privateKey = strings.TrimSpace(os.Getenv("PRIVATEMODE_API_KEY"))
		if privateKey == "" {
			t.Fatal("real rejection requires existing PrivateMode credential")
		}
	}
	for _, streaming := range []bool{false, true} {
		name := "buffered"
		if streaming {
			name = "streaming"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			calls := 0
			if realRejection {
				client, err := privatemode.Start(ctx)
				if err != nil {
					t.Fatal(err)
				}
				llm.ConfigurePrivatemode(client)
			} else {
				llm.ConfigurePrivatemode(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.String() != "https://privatemode.internal:18489/v1/chat/completions" {
						t.Errorf("unexpected PrivateMode transport destination")
					}
					return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
						`{"error":{"message":"active manifest does not match expected manifest"}}`))}, nil
				})})
			}
			t.Cleanup(func() { llm.ConfigurePrivatemode(nil) })
			client := llm.New(&types.BootstrapData{TinfoilAPIKey: key,
				ProviderAPIKeys: map[string]string{"privatemode": privateKey},
			})
			limit := 512
			req := &types.OpenAIChatRequest{Model: "nyte/confidential", Stream: streaming, MaxTokens: &limit}
			body := &types.AnthropicMessagesRequest{MaxTokens: limit, Messages: []types.AnthropicMessage{{Role: "user", Content: "Reply exactly PONG. No explanation."}}}
			verifiedRejections := 0
			observed := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, out io.Writer) error {
				err := client.InvokeStreaming(ctx, req, body, out, option)
				if option.Provider == "privatemode" && err != nil {
					status, _ := llm.HTTPStatusFromError(err)
					if status == 401 && strings.Contains(err.Error(), "attestation manifest changed") {
						verifiedRejections++
					}
				}
				return err
			}}
			options := []llm.InvokeOptions{
				{Provider: "privatemode", Model: "openai/gpt-oss-120b", UpstreamModel: "gpt-oss-120b", EndpointID: "rejected"},
				{Provider: "tinfoil", Model: "openai/gpt-oss-120b", UpstreamModel: "gpt-oss-120b", EndpointID: "live-attested"},
			}
			invocation := startProviderInvocation(ctx, observed, req, body, options, true, nil, "live-confidential-fallback-test")
			defer invocation.abort(context.Canceled)
			output, err := io.ReadAll(io.LimitReader(invocation.reader, 1<<20))
			invocation.join()
			if err != nil {
				t.Fatal(err)
			}
			if verifiedRejections != 1 || (!realRejection && calls != 1) || invocation.selectedRoute.Provider("", nil) != "tinfoil" || invocation.selectedRoute.FallbackCount() != 1 {
				t.Fatal("expected exactly one rejection followed by attested Tinfoil")
			}
			text, input, generated := fallbackLiveResult(t, output)
			if strings.TrimSpace(text) != "PONG" || input <= 0 || generated <= 0 {
				t.Fatalf("unexpected synthetic response=%q input=%d output=%d", text, input, generated)
			}
			t.Logf("real_rejection=%t -> real attested Tinfoil PONG; input=%d output=%d", realRejection, input, generated)
		})
	}
}

func fallbackLiveResult(t *testing.T, stream []byte) (string, int, int) {
	t.Helper()
	type usage struct {
		Input  int `json:"input_tokens"`
		Output int `json:"output_tokens"`
	}
	var text strings.Builder
	input, output := 0, 0
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			continue
		}
		var event struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
			Usage   usage `json:"usage"`
			Message struct {
				Usage usage `json:"usage"`
			} `json:"message"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatal(err)
		}
		text.WriteString(event.Delta.Text)
		input = max(input, event.Usage.Input, event.Message.Usage.Input)
		output = max(output, event.Usage.Output, event.Message.Usage.Output)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return text.String(), input, output
}

func TestFallbackLiveResultJoinsChunks(t *testing.T) {
	stream := []byte("data: {\"message\":{\"usage\":{\"input_tokens\":9}}}\n\ndata: {\"delta\":{\"text\":\"P\"}}\n\ndata: {\"delta\":{\"text\":\"ONG\"}}\n\ndata: {\"usage\":{\"output_tokens\":2}}\n")
	text, input, output := fallbackLiveResult(t, stream)
	if text != "PONG" || input != 9 || output != 2 {
		t.Fatalf("text=%q input=%d output=%d", text, input, output)
	}
}
