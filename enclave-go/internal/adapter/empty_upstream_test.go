package adapter

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCollectAnthropicTextRejectsEmptyEOF(t *testing.T) {
	_, err := CollectAnthropicText(strings.NewReader(""))
	if !errors.Is(err, errEmptyUpstreamResponse) {
		t.Fatalf("error = %v, want empty upstream response", err)
	}
}

func TestTransformStreamCaptureRejectsEmptyEOFWithoutOutput(t *testing.T) {
	var out bytes.Buffer
	_, err := TransformStreamCapture(strings.NewReader(""), &out, "id", "model")
	if !errors.Is(err, errEmptyUpstreamResponse) {
		t.Fatalf("error = %v, want empty upstream response", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, want no client-visible stream", out.String())
	}
}

func TestTransformResponsesStreamRejectsEmptyEOFWithoutOutput(t *testing.T) {
	var out bytes.Buffer
	_, err := TransformResponsesStream(strings.NewReader(""), &out, "resp_id", "model", 1, nil, nil)
	if !errors.Is(err, errEmptyUpstreamResponse) {
		t.Fatalf("error = %v, want empty upstream response", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, want no client-visible stream", out.String())
	}
}

func TestRelayAnthropicStreamRejectsEmptyEOFWithoutOutput(t *testing.T) {
	var out bytes.Buffer
	_, err := RelayAnthropicStream(strings.NewReader(""), &out, "msg_id", "model")
	if !errors.Is(err, errEmptyUpstreamResponse) {
		t.Fatalf("error = %v, want empty upstream response", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, want no client-visible stream", out.String())
	}
}
