package llm

import (
	"fmt"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Provider-internal reasoning and hosted tool executions can only be replayed
// to their originating provider. For other providers the conversation is carried
// by text and client tool_use/tool_result blocks. Never apply this to native
// Anthropic upstreams, which accept these blocks unchanged.
func isProviderHistoryBlock(kind string) bool {
	switch kind {
	case "thinking", "redacted_thinking":
		return true
	default:
		return (kind != "tool_result" && strings.HasSuffix(kind, "_tool_result")) ||
			(kind != "tool_use" && strings.HasSuffix(kind, "_tool_use"))
	}
}

// withoutProviderHistory returns a fresh slice and reports whether dropping
// history emptied it, so callers can omit the message without mutating the
// native body (which may also be dispatched to Anthropic).
func withoutProviderHistory(content any) (any, bool) {
	switch parts := content.(type) {
	case []any:
		return filterProviderHistory(parts, func(part any) string {
			if block, ok := part.(map[string]any); ok {
				return stringValue(block["type"])
			}
			return ""
		})
	case []map[string]any:
		return filterProviderHistory(parts, func(part map[string]any) string { return stringValue(part["type"]) })
	case []qtypes.ChatContentPart:
		return filterProviderHistory(parts, func(part qtypes.ChatContentPart) string { return part.Type })
	default:
		return content, false
	}
}

func filterProviderHistory[T any](parts []T, kind func(T) string) ([]T, bool) {
	out := make([]T, 0, len(parts))
	for _, part := range parts {
		if !isProviderHistoryBlock(kind(part)) {
			out = append(out, part)
		}
	}
	return out, len(parts) > 0 && len(out) == 0
}

// contentInputError marks an unsupported content block as caller input, not a
// provider failure. Keep imageInputError's existing messages and behavior intact.
type contentInputError struct {
	kind    string
	message string
}

func (e *contentInputError) Error() string { return e.ClientInputMessage() }
func (e *contentInputError) ClientInputMessage() string {
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("unsupported content block type %q", e.kind)
}

// textOnlyContent projects block arrays for text-only task formats. Unlike
// ContentText, it reports unsupported blocks instead of silently losing them.
func textOnlyContent(content any) (string, error) {
	switch value := content.(type) {
	case string:
		return value, nil
	case []map[string]any:
		items := make([]any, len(value))
		for i, block := range value {
			items[i] = block
		}
		return textOnlyContent(items)
	case []any:
		text := make([]string, 0, len(value))
		for _, item := range value {
			block, ok := item.(map[string]any)
			if !ok {
				return "", &contentInputError{message: "content block must be an object"}
			}
			kind := stringValue(block["type"])
			switch kind {
			case "", "text", "input_text":
				text = append(text, stringValue(block["text"]))
			default:
				return "", &contentInputError{kind: kind}
			}
		}
		return strings.Join(text, "\n"), nil
	case []qtypes.ChatContentPart:
		text := make([]string, 0, len(value))
		for _, part := range value {
			switch part.Type {
			case "", "text", "input_text":
				text = append(text, part.Text)
			default:
				return "", &contentInputError{kind: part.Type}
			}
		}
		return strings.Join(text, "\n"), nil
	default:
		return "", &contentInputError{kind: fmt.Sprintf("%T", content)}
	}
}
