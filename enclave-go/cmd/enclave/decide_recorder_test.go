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

func TestGenerationRecorderIgnoresWhatFollowsTheStop(t *testing.T) {
	// Once the stream has reached its stop the generation is complete, and what
	// follows is ignored -- in one write or in a later one. Read at the settle
	// hook, a late error used to count only if it happened to arrive before the
	// hook looked, so billing depended on chunk timing.
	answer := adapter.StreamResult{Text: `{"q0":0.9}`, FinishReason: "stop"}
	const delta = "event: content_block_delta\ndata: {}\n\n"
	const stop = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	const lateError = "event: error\ndata: {\"type\":\"error\"}\n\n"
	for label, g := range map[string]*generationRecorder{
		"a stop, then an error, one write":  recorded(delta + stop + lateError),
		"a stop, then an error, two writes": recorded(delta+stop, lateError),
	} {
		if err := g.complete(answer); err != nil {
			t.Errorf("%s: a complete generation was refused: %v", label, err)
		}
	}
	// An error BEFORE the stop is still a provider that failed.
	if err := recorded(delta + lateError + stop).complete(answer); err == nil {
		t.Error("an error before the stop counted as a finished generation")
	}
}

func TestGenerationRecorderIsSafeWhileTheProviderIsStillWriting(t *testing.T) {
	// The collector returns at message_stop, so the settle hook reads while the
	// provider goroutine may still be writing. Run under -race.
	//
	// The one field both sides touch is sawStop, and it is written exactly once,
	// so the reader has to be READING IT when that happens: it spins on the hook
	// for the whole life of the writer, and the whole thing is repeated. (Two
	// earlier versions of this test passed with the lock removed: one let the
	// reader finish first, the other had the writer write a field the hook
	// short-circuits past.)
	for round := 0; round < 200; round++ {
		g := &generationRecorder{}
		written := make(chan struct{})
		go func() {
			defer close(written)
			for i := 0; i < 20; i++ {
				g.Write([]byte("event: content_block_delta\ndata: {}\n\n"))
			}
			g.Write([]byte("event: message_stop\ndata: {}\n\n"))
		}()
		for reading := true; reading; {
			select {
			case <-written:
				reading = false
			default:
				_ = g.complete(adapter.StreamResult{Text: "x", FinishReason: "stop"})
			}
		}
		if err := g.complete(adapter.StreamResult{Text: "x", FinishReason: "stop"}); err != nil {
			t.Fatalf("round %d: a finished stream was refused: %v", round, err)
		}
	}
}
