package main

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/deidentify"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var rampartRunner deidentify.Runner = deidentify.NewWorker("/rampart/node", "/rampart/worker.mjs")

func deidentifyDirectModels(req *types.OpenAIChatRequest) bool {
	direct := func(model string) bool {
		model = types.CanonicalRouterModelID(strings.TrimSpace(model))
		return !isOrchestrationModel(model) && !isGenericAdvisorPrimitive(model)
	}
	if !direct(req.Model) {
		return false
	}
	// Fallback normalization can promote a models entry to the primary model.
	for _, model := range req.Models {
		if !direct(model) {
			return false
		}
	}
	return true
}

func writeDeidentifyError(out io.Writer, route string, err error) {
	status, code, message := 503, "deidentify_unavailable", "De-identification could not complete; request was not sent to a provider"
	if errors.Is(err, deidentify.ErrUnsupported) {
		status, code, message = 400, "deidentify_unsupported", "This request shape is not supported with deidentify enabled"
	}
	if route == "messages" {
		writeAnthropicError(out, status, message)
		return
	}
	errorType := "server_error"
	if status == 400 {
		errorType = "invalid_request_error"
	}
	writeOpenAIError(out, status, message, errorType, code, "deidentify")
}

// No process/model/queue, copy, or context lookup on the disabled path.
func prepareDeidentified(ctx context.Context, enabled bool, body []byte, route string, br llm.Client) ([]byte, llm.Client, error) {
	if !enabled {
		return body, br, nil
	}
	safe, session, err := deidentify.Prepare(ctx, body, route, rampartRunner)
	if err != nil {
		return nil, nil, err
	}
	return safe, &deidentifiedClient{client: br, session: session}, nil
}

type deidentifiedClient struct {
	client  llm.Client
	session *deidentify.Session
}

func (c *deidentifiedClient) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	writer := c.session.Writer(out)
	if err := c.client.InvokeStreaming(ctx, req, body, writer, options...); err != nil {
		return err
	}
	return writer.Close()
}
