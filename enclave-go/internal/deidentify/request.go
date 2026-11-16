package deidentify

import (
	"bytes"
	"context"
	"encoding/json"
)

type textSlot struct {
	value string
	set   func(string)
	fixed bool
}
type projection struct{ slots []textSlot }

// Prepare preserves protocol structure and rejects opaque/remote content. It is
// called only after authentication and only for an explicitly enabled flag.
func Prepare(ctx context.Context, raw []byte, route string, runner Runner) ([]byte, *Session, error) {
	if len(raw) > 256<<10 {
		return nil, nil, ErrUnsupported
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&root) != nil || root == nil {
		return nil, nil, ErrUnsupported
	}
	p := &projection{}
	if err := p.request(root, route); err != nil {
		return nil, nil, err
	}
	if len(p.slots) > 4096 {
		return nil, nil, ErrUnsupported
	}
	texts := make([]string, len(p.slots))
	for i, slot := range p.slots {
		texts[i] = slot.value
	}
	result, err := runner.Protect(ctx, texts)
	if err != nil {
		return nil, nil, err
	}
	if len(result.Texts) != len(texts) {
		return nil, nil, ErrUnavailable
	}
	for i, slot := range p.slots {
		if slot.fixed && result.Texts[i] != slot.value {
			return nil, nil, ErrUnsupported
		}
		if !slot.fixed {
			slot.set(result.Texts[i])
		}
	}
	delete(root, "deidentify")
	safe, err := json.Marshal(root)
	if err != nil {
		return nil, nil, ErrUnsupported
	}
	return safe, &Session{replacements: result.Replacements}, nil
}

func (p *projection) text(v any, set func(string), fixed bool) error {
	s, ok := v.(string)
	if !ok {
		return ErrUnsupported
	}
	p.slots = append(p.slots, textSlot{s, set, fixed})
	return nil
}

// Free-form JSON (tool inputs, schemas and metadata) is walked structurally,
// not edited as serialized JSON. Identifiers/keys cannot change unnoticed.
func (p *projection) free(v any, set func(any)) error {
	switch x := v.(type) {
	case string:
		return p.text(x, func(s string) { set(s) }, false)
	case []any:
		for i, child := range x {
			if err := p.free(child, func(v any) { x[i] = v }); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, child := range x {
			if err := p.text(key, nil, true); err != nil {
				return err
			}
			if err := p.free(child, func(v any) { x[key] = v }); err != nil {
				return err
			}
		}
	case json.Number:
		// Redacting a numeric identifier to a string would violate tool schemas.
		return p.text(x.String(), nil, true)
	case nil, bool:
	default:
		return ErrUnsupported
	}
	return nil
}

func (p *projection) field(m map[string]any, key string, fixed bool) error {
	return p.text(m[key], func(s string) { m[key] = s }, fixed)
}

func (p *projection) jsonString(m map[string]any, key string) error {
	s, ok := m[key].(string)
	if !ok {
		return ErrUnsupported
	}
	var value any
	decoder := json.NewDecoder(bytes.NewBufferString(s))
	decoder.UseNumber()
	if !json.Valid([]byte(s)) || decoder.Decode(&value) != nil {
		return ErrUnsupported
	}
	// Keep the parsed value alive until all setters run, then serialize it in a
	// final slot. This avoids replacement text breaking escaping in tool JSON.
	if err := p.free(value, func(v any) { value = v }); err != nil {
		return err
	}
	p.slots = append(p.slots, textSlot{"", func(_ string) { b, _ := json.Marshal(value); m[key] = string(b) }, false})
	return nil
}

func (p *projection) content(v any, set func(any)) error {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return p.text(x, func(s string) { set(s) }, false)
	case []any:
		for _, child := range x {
			block, ok := child.(map[string]any)
			if !ok {
				return ErrUnsupported
			}
			kind, _ := block["type"].(string)
			switch kind {
			case "text", "input_text", "output_text", "tool_result", "tool_use":
			default:
				return ErrUnsupported
			}
			for key, value := range block {
				switch key {
				case "type":
				case "text":
					if err := p.field(block, key, false); err != nil {
						return err
					}
				case "content":
					if err := p.content(value, func(v any) { block[key] = v }); err != nil {
						return err
					}
				case "input":
					if kind != "tool_use" {
						return ErrUnsupported
					}
					if err := p.free(value, func(v any) { block[key] = v }); err != nil {
						return err
					}
				case "id", "tool_use_id", "name":
					if err := p.field(block, key, true); err != nil {
						return err
					}
				case "is_error":
					if _, ok := value.(bool); !ok {
						return ErrUnsupported
					}
				case "cache_control":
					if err := p.cache(value); err != nil {
						return err
					}
				default:
					return ErrUnsupported
				}
			}
		}
	default:
		return ErrUnsupported
	}
	return nil
}

func (p *projection) cache(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return ErrUnsupported
	}
	for k, v := range m {
		if (k != "type" || v != "ephemeral") && (k != "ttl" || (v != "5m" && v != "1h")) {
			return ErrUnsupported
		}
	}
	return nil
}

func (p *projection) messages(v any) error {
	list, ok := v.([]any)
	if !ok {
		return ErrUnsupported
	}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return ErrUnsupported
		}
		for key, value := range m {
			switch key {
			case "role":
				role, _ := value.(string)
				if !oneOf(role, "system", "developer", "user", "assistant", "tool") {
					return ErrUnsupported
				}
			case "type":
				kind, _ := value.(string)
				if !oneOf(kind, "message", "function_call", "function_call_output") {
					return ErrUnsupported
				}
			case "content":
				if err := p.content(value, func(v any) { m[key] = v }); err != nil {
					return err
				}
			case "output":
				if err := p.free(value, func(v any) { m[key] = v }); err != nil {
					return err
				}
			case "arguments":
				if err := p.jsonString(m, key); err != nil {
					return err
				}
			case "name", "tool_call_id", "call_id", "id":
				if err := p.field(m, key, true); err != nil {
					return err
				}
			case "status":
				if !oneOf(value, "completed", "in_progress", "incomplete") {
					return ErrUnsupported
				}
			case "tool_calls":
				calls, ok := value.([]any)
				if !ok {
					return ErrUnsupported
				}
				for _, call := range calls {
					if err := p.toolCall(call); err != nil {
						return err
					}
				}
			default:
				return ErrUnsupported
			}
		}
	}
	return nil
}

func (p *projection) toolCall(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return ErrUnsupported
	}
	for k, v := range m {
		switch k {
		case "type":
			if v != "function" {
				return ErrUnsupported
			}
		case "id":
			if err := p.field(m, k, true); err != nil {
				return err
			}
		case "function":
			f, ok := v.(map[string]any)
			if !ok {
				return ErrUnsupported
			}
			for k := range f {
				switch k {
				case "name":
					if err := p.field(f, k, true); err != nil {
						return err
					}
				case "arguments":
					if err := p.jsonString(f, k); err != nil {
						return err
					}
				default:
					return ErrUnsupported
				}
			}
		default:
			return ErrUnsupported
		}
	}
	return nil
}

func (p *projection) tools(v any) error {
	list, ok := v.([]any)
	if !ok {
		return ErrUnsupported
	}
	for _, tool := range list {
		m, ok := tool.(map[string]any)
		if !ok {
			return ErrUnsupported
		}
		for k, v := range m {
			switch k {
			case "type":
				if v != "function" {
					return ErrUnsupported
				}
			case "function":
				if err := p.tools([]any{v}); err != nil {
					return err
				}
			case "name":
				if err := p.field(m, k, true); err != nil {
					return err
				}
			case "description", "parameters", "input_schema":
				if err := p.free(v, func(v any) { m[k] = v }); err != nil {
					return err
				}
			case "strict":
				if _, ok := v.(bool); !ok {
					return ErrUnsupported
				}
			default:
				return ErrUnsupported
			}
		}
	}
	return nil
}

func (p *projection) request(m map[string]any, route string) error {
	if !oneOf(route, "chat.completions", "responses", "messages") {
		return ErrUnsupported
	}
	for key, value := range m {
		switch key {
		case "deidentify":
			if value != true {
				return ErrUnsupported
			}
		case "messages":
			if err := p.messages(value); err != nil {
				return err
			}
		case "input":
			if s, ok := value.(string); ok {
				if err := p.text(s, func(s string) { m[key] = s }, false); err != nil {
					return err
				}
			} else if err := p.messages(value); err != nil {
				return err
			}
		case "system":
			if err := p.content(value, func(v any) { m[key] = v }); err != nil {
				return err
			}
		case "instructions", "stop", "stop_sequences", "metadata", "user", "session_id", "trace", "tags", "safety_identifier":
			if err := p.free(value, func(v any) { m[key] = v }); err != nil {
				return err
			}
		case "tools":
			if err := p.tools(value); err != nil {
				return err
			}
		case "tool_choice":
			if err := p.free(value, func(v any) { m[key] = v }); err != nil {
				return err
			}
		case "response_format", "text":
			if err := p.free(value, func(v any) { m[key] = v }); err != nil {
				return err
			}
		case "model", "models", "provider": // Validated routing controls, not prompt text.
		case "stream", "stream_options", "temperature", "top_p", "top_k", "top_a", "min_p", "frequency_penalty", "presence_penalty", "repetition_penalty", "repeat_penalty", "max_tokens", "max_completion_tokens", "max_output_tokens", "n", "seed", "parallel_tool_calls", "max_tool_calls", "logit_bias", "logprobs", "top_logprobs", "reasoning", "reasoning_effort", "thinking", "output_config", "enable_thinking", "include_reasoning", "service_tier", "usage", "store", "background", "include", "truncation", "allow_fallbacks", "modalities":
			// Validate any strings in these controls against the small protocol
			// vocabulary. Arbitrary strings are not an unscanned escape hatch.
			if !controlValue(value) {
				return ErrUnsupported
			}
		default:
			return ErrUnsupported
		}
	}
	return nil
}

func oneOf(v any, values ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range values {
		if s == x {
			return true
		}
	}
	return false
}
func controlValue(v any) bool {
	switch x := v.(type) {
	case nil, bool, json.Number:
		return true
	case string:
		return oneOf(x, "auto", "none", "low", "medium", "high", "xhigh", "minimal", "max", "enabled", "disabled", "adaptive", "text", "default", "priority", "flex", "concise", "detailed", "reasoning.encrypted_content", "message.output_text.logprobs")
	case []any:
		for _, v := range x {
			if !controlValue(v) {
				return false
			}
		}
		return true
	case map[string]any:
		for k, v := range x {
			if !oneOf(k, "effort", "type", "enabled", "exclude", "summary", "budget_tokens", "max_tokens", "include_usage", "include", "format") || !controlValue(v) {
				return false
			}
		}
		return true
	}
	return false
}
