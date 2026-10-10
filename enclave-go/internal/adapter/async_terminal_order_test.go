package adapter

import (
	"bytes"
	"strings"
	"testing"
)

func TestAsyncStageDTerminalOrder(t *testing.T) {
	for _, route := range []string{"responses", "chat"} {
		for _, reason := range []string{"cap_reached", "heartbeat_lost"} {
			t.Run(route+"/"+reason, func(t *testing.T) {
				var out bytes.Buffer
				seen, metadataCalls := 0, 0
				control := &StreamControl{
					BeforeSlice: func(delta StreamDelta) error {
						if delta.Type == "text_delta" {
							seen++
						}
						if seen == 2 {
							return &ControlledTermination{FinishReason: "length", TRFinishReason: reason}
						}
						return nil
					},
					BeforeTerminal: func(terminal StreamTerminal) error { return terminal.Emit() },
					AfterTerminal: func(StreamResult) (map[string]any, error) {
						metadataCalls++
						return map[string]any{"trusted_router_settlement": map[string]any{"settlement_status": "settled"}}, nil
					},
				}
				var err error
				terminal := `"tr_finish_reason":"` + reason + `"`
				if route == "responses" {
					_, err = TransformResponsesStreamControlled(strings.NewReader(stageDTextProvider()), &out, "id", "model", 1, nil, nil, nil, control)
					terminal = "event: response.incomplete"
				} else {
					_, err = TransformStreamCaptureControlled(strings.NewReader(stageDTextProvider()), &out, "id", "model", true, nil, nil, control)
				}
				if err != nil {
					t.Fatal(err)
				}
				wire := out.String()
				meta := strings.Index(wire, `"trusted_router_settlement"`)
				end := strings.Index(wire, terminal)
				if metadataCalls != 1 || meta < 0 || end < meta || strings.Count(wire, "data: [DONE]") != 1 || !strings.HasSuffix(wire, "data: [DONE]\n\n") {
					t.Fatalf("terminal order: %s", wire)
				}
				if route == "responses" {
					closed := strings.Index(wire, "event: response.output_item.done")
					if closed < 0 || closed > meta {
						t.Fatalf("closing events must precede metadata: %s", wire)
					}
				}
			})
		}
	}
}
