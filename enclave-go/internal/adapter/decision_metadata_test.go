package adapter

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestChatWithoutProviderMetadataIsByteIdentical(t *testing.T) {
	var base, extended bytes.Buffer
	usage := &StreamUsage{InputTokens: 100, OutputTokens: 10, CacheReadInputTokens: 80}
	if err := WriteChatCompletionResponse(&base, "id", "model", "answer", "thinking", nil, 100, 10, usage, 123, "stop"); err != nil {
		t.Fatal(err)
	}
	if err := WriteChatCompletionResponseWithProviderMetadata(&extended, "id", "model", "answer", "thinking", nil, 100, 10, usage, 123, "stop", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base.Bytes(), extended.Bytes()) {
		t.Fatal("ordinary response changed")
	}
}

func TestDecisionChunkWaitsForTerminalGate(t *testing.T) {
	native := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"answer\"}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"trustedrouter_decision\":{\"confidence\":0.9}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	blocked := errors.New("terminal gate blocked")
	var out bytes.Buffer
	_, err := TransformStreamCaptureControlled(strings.NewReader(native), &out, "id", "model", false, nil, nil, &StreamControl{
		BeforeTerminal: func(terminal StreamTerminal) error {
			if terminal.Result.Decision["confidence"] != 0.9 {
				t.Fatal("terminal result lost decision")
			}
			return blocked
		},
	})
	if !errors.Is(err, blocked) || strings.Contains(out.String(), `"decision"`) || strings.Contains(out.String(), "[DONE]") {
		t.Fatalf("metadata bypassed terminal gate: %v %s", err, out.String())
	}
}
