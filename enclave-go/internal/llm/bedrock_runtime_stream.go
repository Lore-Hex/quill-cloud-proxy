//go:build llm_multi

package llm

import (
	"encoding/json"
	"fmt"
)

// Retain provider usage snapshots, never sum cumulative stream counters.
type bedrockRuntimeStream struct {
	started, stopped, finalUsage bool
	usage                        map[string]int64
}

func (s *bedrockRuntimeStream) accept(payload []byte) (bool, error) {
	invalid := func() (bool, error) {
		return false, fmt.Errorf("llm/bedrock-runtime: invalid stream record or usage")
	}
	var event struct {
		Type    string                     `json:"type"`
		Usage   map[string]json.RawMessage `json:"usage"`
		Message struct {
			Role  string                     `json:"role"`
			Usage map[string]json.RawMessage `json:"usage"`
		} `json:"message"`
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	}
	if len(payload) > 16<<20 || json.Unmarshal(payload, &event) != nil || s.stopped {
		return invalid()
	}
	switch event.Type {
	case "message_start":
		if s.started || event.Message.Role != "assistant" ||
			!s.acceptUsage(event.Message.Usage, true) {
			return invalid()
		}
		s.started = true
	case "message_delta":
		if !s.started || s.finalUsage || !s.acceptUsage(event.Usage, false) {
			return invalid()
		}
		if event.Delta.StopReason != "" {
			s.finalUsage = true
		}
	case "message_stop":
		if !s.started || !s.finalUsage {
			return invalid()
		}
		s.stopped = true
		return true, nil
	case "content_block_start", "content_block_delta", "content_block_stop":
		if !s.started || s.finalUsage {
			return invalid()
		}
	case "ping":
	default:
		return invalid()
	}
	return false, nil
}

func (s *bedrockRuntimeStream) acceptUsage(usage map[string]json.RawMessage, initial bool) bool {
	if usage == nil || usage["output_tokens"] == nil || (initial && usage["input_tokens"] == nil) {
		return false
	}
	if s.usage == nil {
		s.usage = make(map[string]int64)
	}
	for _, field := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"} {
		if raw, ok := usage[field]; ok {
			var count *int64
			if json.Unmarshal(raw, &count) != nil || count == nil || *count < s.usage[field] || *count > 1<<31 {
				return false
			}
			s.usage[field] = *count
		}
	}
	return true
}
