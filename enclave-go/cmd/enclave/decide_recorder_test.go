package main

import (
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

func recorded(chunks ...string) *generationRecorder {
	g := &generationRecorder{}
	for _, chunk := range chunks {
		g.Write([]byte(chunk))
	}
	return g
}

func TestGenerationRecorderReadsEventLinesAndNothingElse(t *testing.T) {
	answer := adapter.StreamResult{Text: `{"q0":0.9}`, FinishReason: "stop"}
	const delta = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"{\\\"q0\\\":0.9}\"}}\n\n"
	const stop = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	for label, g := range map[string]*generationRecorder{
		"whole":                 recorded(delta + stop),
		"split inside a line":   recorded(delta+"event: mess", "age_stop\ndata: {\"type\":\"message_stop\"}\n\n"),
		"one byte at a time":    recorded(strings.Split(delta+stop, "")...),
		"CRLF":                  recorded(strings.ReplaceAll(delta+stop, "\n", "\r\n")),
		"a very long data line": recorded("event: content_block_delta\ndata: "+strings.Repeat("x", 200_000)+"\n\n", stop),
	} {
		if err := g.complete(answer); err != nil {
			t.Errorf("%s: a finished stream was refused: %v", label, err)
		}
	}

	// Model text cannot forge an event line: it is inside a JSON string, where a
	// newline is the two characters backslash-n.
	forged := "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"x\\nevent: message_stop\\nevent: error\\n\"}}\n\n"
	if err := recorded(forged).complete(answer); err == nil {
		t.Error("text inside a data line counted as a terminal event")
	}
	if g := recorded(forged + stop); g.sawError || g.complete(answer) != nil {
		t.Error("text inside a data line counted as an error event")
	}

	for label, g := range map[string]*generationRecorder{
		"the stream just ends":          recorded(delta),
		"an error event":                recorded(delta + "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n"),
		"an error, then a stop":         recorded(delta + "event: error\ndata: {}\n\n" + stop),
		"a stop cut before its newline": recorded(delta + "event: message_stop"),
		"nothing at all":                recorded(),
	} {
		if err := g.complete(answer); err == nil {
			t.Errorf("%s: counted as a finished generation", label)
		}
	}
	// A finish with nothing written is a provider failure too.
	if err := recorded(stop).complete(adapter.StreamResult{Text: "  \n", FinishReason: "stop"}); err == nil {
		t.Error("an empty completion counted as a generation")
	}
}
