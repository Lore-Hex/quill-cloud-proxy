// Package llm is the upstream-model gateway. The enclave talks to a
// remote LLM (Anthropic Claude) through one of two providers:
//
//   - AWS Bedrock, when built with the default (`-tags ''`) or `-tags aws`
//     build tag. Implementation in aws.go (which wraps internal/bedrock).
//   - Google Vertex AI, when built with `-tags gcp`. Implementation in
//     gcp.go.
//
// The same Quill source tree produces two distinct enclave binaries:
//
//   go build -tags aws ./cmd/enclave   # AWS Nitro target (Bedrock)
//   go build -tags gcp ./cmd/enclave   # GCP Confidential Space (Vertex)
//
// Each binary has only the provider-specific code that's relevant to it,
// so the per-cloud measurement (PCR0 on Nitro, image digest on
// Confidential Space) is minimum-surface.
package llm

import (
	"context"
	"io"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Client is the upstream gateway. The single method that matters is
// InvokeStreaming — the enclave parses an OpenAI request, translates to
// Anthropic Messages shape, and hands the body to the Client; the Client
// is responsible for talking to the underlying provider (Bedrock or
// Vertex AI) and writing the upstream's native Anthropic SSE bytes into
// `out`. The adapter package downstream translates SSE → OpenAI chunks.
type Client interface {
	InvokeStreaming(
		ctx context.Context,
		modelName string,
		body *qtypes.AnthropicMessagesRequest,
		out io.Writer,
	) error
}

// New builds the right Client for the build target. Defined exactly once
// per build tag — see aws.go and gcp.go.
