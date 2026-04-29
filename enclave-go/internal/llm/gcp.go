//go:build gcp

// Google Vertex AI provider. Opt in with `-tags gcp`.
//
// Calls the Anthropic-on-Vertex API via the official anthropic-sdk-go
// vertex backend. The backend uses Application Default Credentials, which
// inside Confidential Space come from Workload Identity Federation —
// short-lived, attestation-bound, and scoped to the workload's service
// account.
//
// The vertex backend speaks the same Messages API as the direct Anthropic
// API, with two differences: model is in the URL (not the body) and
// `anthropic_version` must equal `vertex-2023-10-16`. The SDK handles
// both internally.
//
// Streaming: the SDK exposes an iterator of MessageStreamEvent; we
// re-emit each one as a native Anthropic SSE event (`event: name\ndata:
// {...}\n\n`) so the existing adapter package downstream needs no
// changes.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/vertex"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type gcpClient struct {
	client *anthropic.Client
}

// modelMap is empty by design — Vertex uses the same Anthropic model
// names we accept on the wire (claude-opus-4-7, claude-sonnet-4-6, etc),
// so no remapping is needed. We keep the function for symmetry with the
// AWS path's MapModel and to gate unsupported names.
var supportedModels = map[string]bool{
	"claude-opus-4-7":           true,
	"claude-sonnet-4-6":         true,
	"claude-haiku-4-5-20251001": true,
}

func (c *gcpClient) InvokeStreaming(
	ctx context.Context,
	modelName string,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
) error {
	if !supportedModels[modelName] {
		return fmt.Errorf("llm/gcp: unknown model: %s", modelName)
	}

	// Translate qtypes.AnthropicMessagesRequest → anthropic.MessageNewParams.
	// Both speak the same wire shape; the local struct exists so other
	// internal packages can pass it around without depending on the SDK.
	msgs := make([]anthropic.MessageParam, 0, len(body.Messages))
	for _, m := range body.Messages {
		switch m.Role {
		case "user":
			msgs = append(msgs, anthropic.NewUserMessage(anthropic.NewTextBlock(m.Content)))
		case "assistant":
			msgs = append(msgs, anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Content)))
		default:
			return fmt.Errorf("llm/gcp: unsupported role: %s", m.Role)
		}
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(modelName),
		MaxTokens: int64(body.MaxTokens),
		Messages:  msgs,
	}
	if body.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: body.System}}
	}
	if body.Temperature != nil {
		params.Temperature = anthropic.Float(*body.Temperature)
	}
	if body.TopP != nil {
		params.TopP = anthropic.Float(*body.TopP)
	}

	stream := c.client.Messages.NewStreaming(ctx, params)
	for stream.Next() {
		event := stream.Current()
		// Re-emit the event in native Anthropic SSE format so the existing
		// adapter package can parse it without knowing it came from Vertex.
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("llm/gcp: marshal event: %w", err)
		}
		if _, err := fmt.Fprintf(out, "event: %s\ndata: %s\n\n", event.Type, data); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		return fmt.Errorf("llm/gcp: stream: %w", err)
	}
	return nil
}

func New(boot *qtypes.BootstrapData) Client {
	// Project + region come from env. Operator sets them on the workload
	// container at deploy time; in a Confidential Space VM they're injected
	// from the workload spec.
	projectID := os.Getenv("QUILL_GCP_PROJECT_ID")
	region := os.Getenv("QUILL_GCP_REGION") // e.g. "global", "us-east1"
	if region == "" {
		region = "global"
	}

	client := anthropic.NewClient(
		vertex.WithGoogleAuth(context.Background(), region, projectID),
		option.WithMaxRetries(2),
	)
	return &gcpClient{client: &client}
}
