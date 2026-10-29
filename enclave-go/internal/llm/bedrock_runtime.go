//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go/auth/bearer"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// Exact US profiles only: never map an unknown Claude or silently use Mantle/global.
var bedrockRuntimeModels = map[string]string{
	"anthropic/claude-sonnet-5.5": "us.anthropic.claude-sonnet-5-5",
	"anthropic/claude-opus-5.5":   "us.anthropic.claude-opus-5-5",
	"anthropic/claude-haiku-5.5":  "us.anthropic.claude-haiku-5-5",
	"anthropic/claude-sonnet-5":   "us.anthropic.claude-sonnet-5",
	"anthropic/claude-opus-4.8":   "us.anthropic.claude-opus-4-8",
}

type bedrockRuntimeClient struct {
	apiKey string
	httpc  *http.Client
	br     *bedrockruntime.Client
}

func newBedrockRuntime(apiKey string) *bedrockRuntimeClient {
	return newBedrockRuntimeWithHTTP(apiKey, defaultHTTPClient())
}

func newBedrockRuntimeWithHTTP(apiKey string, httpc *http.Client) *bedrockRuntimeClient {
	// Never follow an upstream redirect carrying the managed credential or prompt.
	client := *httpc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = defaultStreamingHTTPTimeout
	key := strings.TrimSpace(apiKey)
	return &bedrockRuntimeClient{
		apiKey: key, httpc: &client,
		br: bedrockruntime.NewFromConfig(aws.Config{
			Region: "us-east-1", HTTPClient: streamhttp.Client{Base: &client},
			BearerAuthTokenProvider: bearer.StaticTokenProvider{Token: bearer.Token{Value: key}},
			RetryMaxAttempts:        1,
		}),
	}
}

func (c *bedrockRuntimeClient) requireZeroRetention(ctx context.Context) error {
	// No cached positive result: every dispatch checks all allowed US destinations.
	// The account policy additionally blocks incompatible models inside Bedrock.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, region := range []string{"us-east-1", "us-east-2", "us-west-2"} {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://bedrock."+region+".amazonaws.com/data-retention", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		resp, err := c.httpc.Do(req)
		if err != nil {
			return fmt.Errorf("llm/bedrock-runtime: retention verification unavailable")
		}
		var policy struct {
			Mode string `json:"mode"`
		}
		payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		if readErr != nil || len(payload) > 4096 {
			return &upstreamHTTPError{status: 503, body: "Bedrock Runtime zero-retention policy could not be verified"}
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decodeErr := decoder.Decode(&policy)
		var extra any
		trailingErr := decoder.Decode(&extra)
		if resp.StatusCode != 200 || decodeErr != nil || trailingErr != io.EOF || policy.Mode != "none" {
			return &upstreamHTTPError{status: 503, body: "Bedrock Runtime zero-retention policy could not be verified"}
		}
	}
	return nil
}

func (c *bedrockRuntimeClient) InvokeStreaming(ctx context.Context, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, out io.Writer, options ...InvokeOptions) error {
	option := firstOptions(options)
	if c == nil || c.apiKey == "" || req == nil || body == nil || option.ProviderAPIKey != "" {
		return fmt.Errorf("llm/bedrock-runtime: managed credentials and request required")
	}
	profile, ok := bedrockRuntimeModels[req.Model]
	if !ok || profile != option.UpstreamModel {
		return fmt.Errorf("llm/bedrock-runtime: unapproved model/profile pair")
	}
	if req.ServiceTier != "" && req.ServiceTier != "default" && req.ServiceTier != "standard" {
		return &upstreamHTTPError{status: 400, body: "Bedrock Runtime supports the standard service tier only"}
	}
	if err := validateBedrockRuntimeCacheTTL(body); err != nil {
		return err
	}
	if err := c.requireZeroRetention(ctx); err != nil {
		return err
	}
	converted, err := anthropicBodyWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	converted = anthropicChatReasoningBody(strings.TrimPrefix(profile, "us.anthropic."), req, converted)
	projection := *converted
	projection.AnthropicVersion = "bedrock-2023-05-31"
	projection.Temperature = anthropicTemperature(strings.TrimPrefix(profile, "us.anthropic."), converted.Temperature)
	payload, err := json.Marshal(bedrock.BuildRequestShape(&projection))
	if err != nil {
		return err
	}
	response, err := c.br.InvokeModelWithResponseStream(ctx, &bedrockruntime.InvokeModelWithResponseStreamInput{
		ModelId: aws.String(profile), ContentType: aws.String("application/json"), Accept: aws.String("application/json"), Body: payload,
	})
	if err != nil {
		var responseError interface{ HTTPStatusCode() int }
		if errors.As(err, &responseError) && responseError.HTTPStatusCode() >= 400 && responseError.HTTPStatusCode() <= 599 {
			return &upstreamHTTPError{status: responseError.HTTPStatusCode(), body: "Bedrock Runtime inference request failed"}
		}
		return fmt.Errorf("llm/bedrock-runtime: inference request failed")
	}
	stream := response.GetStream()
	defer stream.Close()
	upstreamerror.Open(out)
	var state bedrockRuntimeStream
	for event := range stream.Events() {
		chunk, ok := event.(*bedrocktypes.ResponseStreamMemberChunk)
		if !ok {
			return fmt.Errorf("llm/bedrock-runtime: upstream stream exception")
		}
		terminal, err := state.accept(chunk.Value.Bytes)
		if err != nil {
			return err
		}
		if terminal {
			continue
		}
		if err := bedrock.RelayEvent(chunk.Value.Bytes, out); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		return fmt.Errorf("llm/bedrock-runtime: upstream stream failed")
	}
	if !state.stopped {
		return fmt.Errorf("llm/bedrock-runtime: missing terminal record")
	}
	// SDK framing errors or exception events after the model's terminal record
	// must not reach settlement as a successful completed response.
	return bedrock.RelayEvent([]byte(`{"type":"message_stop"}`), out)
}

func validateBedrockRuntimeCacheTTL(body *qtypes.AnthropicMessagesRequest) error {
	// The shared cache-write ledger currently represents only the 5m tariff.
	if err := validateVertexClaudeCacheTTL(body); err != nil {
		return &upstreamHTTPError{status: 400, body: "Bedrock Runtime supports only five-minute cache writes"}
	}
	return nil
}
