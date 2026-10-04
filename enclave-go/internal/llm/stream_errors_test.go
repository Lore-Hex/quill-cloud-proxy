package llm

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestProviderStreamErrorEvents(t *testing.T) {
	const failure = `{"error":{"message":"Policy refusal","type":"content_policy_error","code":400}}`
	const content = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"partial\",\"type\":\"text_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n\n"
	for _, tc := range []struct {
		name, prefix, event string
		translate           func(io.Reader, io.Writer) error
	}{
		{"openai", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", "data:" + failure + "\n\n", translateOpenAIStreamToAnthropic},
		{"tencent", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", "data: " + failure + "\n\n", func(r io.Reader, w io.Writer) error {
			return translateOpenAIStreamToAnthropicForProvider(r, w, "tencent")
		}},
		{"delta", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", "data: {\"choices\":[{\"delta\":" + failure + "}]}\n\n", translateOpenAIStreamToAnthropic},
		{"anthropic", content, "event: error\ndata: " + failure + "\n\n", relayAnthropicStream},
		{"responses", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n", "data: {\"type\":\"response.failed\",\"response\":" + failure + "}\n\n", translateOpenAIResponsesStream},
	} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/partial=%t", tc.name, partial), func(t *testing.T) {
				wire, want := tc.event, ""
				if partial {
					wire = tc.prefix + wire
					want = content
				}
				var out bytes.Buffer
				err := tc.translate(strings.NewReader(wire), &out)
				if err == nil {
					t.Fatal("error event was ignored")
				}
				got := upstreamerror.Parse(err)
				if got.Status != 400 || got.Message != "Policy refusal" || got.Type != "content_policy_error" || out.String() != want {
					t.Fatalf("error=%#v body=%q want=%q", got, out.String(), want)
				}
				if status, ok := HTTPStatusFromError(err); !ok || status != 400 {
					t.Fatalf("status=%d ok=%t", status, ok)
				}
			})
		}
	}
}

type streamOpenTestWriter struct {
	bytes.Buffer
	opened bool
}

func (w *streamOpenTestWriter) UpstreamOpened() bool { w.opened = true; return true }

type streamOpenTestReader struct {
	t        *testing.T
	out      *streamOpenTestWriter
	accepted bool
	*strings.Reader
}

func (r *streamOpenTestReader) Read(p []byte) (int, error) {
	r.t.Helper()
	if r.out.opened != r.accepted {
		r.t.Fatalf("body read: opened=%t want=%t", r.out.opened, r.accepted)
	}
	return r.Reader.Read(p)
}

type streamErrorTransport func(*http.Request) (*http.Response, error)

func (f streamErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpstreamOpenPrecedesBodyRead(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic"} {
		for _, status := range []int{200, 201, 400} {
			t.Run(fmt.Sprintf("%s/%d", provider, status), func(t *testing.T) {
				out := &streamOpenTestWriter{}
				body := `{"error":{"message":"rejected"}}`
				if status < 300 {
					if provider == "anthropic" {
						body = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
					} else {
						body = "data: [DONE]\n\n"
					}
				}
				calls := 0
				client := &http.Client{Transport: streamErrorTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(&streamOpenTestReader{t: t, out: out, accepted: status < 300, Reader: strings.NewReader(body)}), Request: r}, nil
				})}
				req := &qtypes.OpenAIChatRequest{Model: "test", Stream: true}
				native := &qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}}}
				var err error
				if provider == "anthropic" {
					err = invokeAnthropicCompatibleStreamingWithClient(context.Background(), client, provider, "https://provider.invalid/v1/messages", false, req, native, out, "test-key", "test")
				} else {
					err = invokeOpenAICompatibleStreamingWithClientOptions(context.Background(), client, provider, "https://provider.invalid/v1/chat/completions", "test-key", req, native, out, "test", openAICompatibleInvocationOptions{})
				}
				if calls != 1 {
					t.Fatalf("calls=%d", calls)
				}
				if status >= 400 {
					d := upstreamerror.Parse(err)
					if err == nil || d.Status != 400 || d.Message != "rejected" || out.Len() != 0 {
						t.Fatalf("err=%v body=%q", err, out.String())
					}
				} else if err != nil || !out.opened {
					t.Fatalf("err=%v opened=%t", err, out.opened)
				}
			})
		}
	}
}

func TestNativeStreamEventSizeBound(t *testing.T) {
	var out bytes.Buffer
	err := relayAnthropicStream(strings.NewReader(strings.Repeat(": comment\n", (1<<20)/10+1)), &out)
	if err != io.ErrShortBuffer || out.Len() != 0 {
		t.Fatalf("err=%v bytes=%d", err, out.Len())
	}
}

func TestChutesDoesNotRetryAfterOpen(t *testing.T) {
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	const chuteID = "aac09863-35b4-5d9b-9b67-6e6a9d54273a"
	calls := 0
	client := newChutesE2EE("test-key")
	client.httpc = &http.Client{Transport: streamErrorTransport(func(r *http.Request) (*http.Response, error) {
		body := "{}"
		switch {
		case strings.HasPrefix(r.URL.Path, "/e2e/instances/"):
			encoded, _ := json.Marshal(chutesDiscoveryResponse{NonceExpiresIn: 60, Instances: []chutesInstance{
				{InstanceID: "first", E2EPubkey: base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()), Nonces: []string{"one"}},
				{InstanceID: "second", E2EPubkey: base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()), Nonces: []string{"two"}},
			}})
			body = string(encoded)
		case strings.HasPrefix(r.URL.Path, "/instances/"):
		case r.URL.Path == "/e2e/invoke":
			calls++
			body = "data: {\"invalid_encrypted_event\":true}\n\n"
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	client.verifyEvidence = func(context.Context, *chutesEvidenceEnvelope) (*chutesVerificationResult, error) {
		return &chutesVerificationResult{VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), Policy: "chutes-tdx-nvidia-e2e-v1"}, nil
	}
	out := &streamOpenTestWriter{}
	err = client.InvokeStreaming(context.Background(), &qtypes.OpenAIChatRequest{Model: chuteID, Stream: true}, &qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}}}, out, InvokeOptions{Provider: "chutes", UpstreamModel: chuteID})
	if err == nil || !out.opened || out.Len() != 0 || calls != 1 {
		t.Fatalf("err=%v opened=%t body=%q calls=%d", err, out.opened, out.String(), calls)
	}
}
