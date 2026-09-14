package phalaaci

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// EncryptChat deliberately supports only v2-defined content locations. Tool
// definitions, tool arguments, schemas, and caller metadata have no encrypted
// representation in this protocol and must never leak through a passthrough.
func (e *Encryption) EncryptChat(raw []byte, sessionID string) ([]byte, string, error) {
	var body map[string]json.RawMessage
	if err := Decode(raw, &body); err != nil {
		return nil, "", err
	}
	allowed := map[string]bool{"model": true, "messages": true, "stream": true, "stream_options": true,
		"max_tokens": true, "max_completion_tokens": true, "temperature": true, "top_p": true, "top_k": true,
		"frequency_penalty": true, "presence_penalty": true, "seed": true, "thinking": true, "reasoning": true}
	for key := range body {
		if !allowed[key] {
			return nil, "", errors.New("ACI E2EE v2 cannot protect this request field")
		}
	}
	if err := validateChatControls(body); err != nil {
		return nil, "", err
	}
	var model string
	if json.Unmarshal(body["model"], &model) != nil || model != e.Model || !IsHex(sessionID, 32) {
		return nil, "", errors.New("ACI request model/session mismatch")
	}
	// The server must use the exact preflighted session, never an unattested
	// substitute or model fallback hidden behind its own router.
	provider, err := CanonicalValue(map[string]any{"aci_verified": true, "aci_session_ids": []string{sessionID}, "allow_fallbacks": false})
	if err != nil {
		return nil, "", err
	}
	body["provider"] = provider
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(body["messages"], &messages); err != nil || len(messages) == 0 {
		return nil, "", errors.New("ACI messages missing")
	}
	for _, message := range messages {
		for key := range message {
			if key != "role" && key != "content" {
				return nil, "", errors.New("ACI E2EE v2 cannot protect tool/name fields")
			}
		}
		var role string
		if json.Unmarshal(message["role"], &role) != nil || (role != "system" && role != "developer" && role != "user" && role != "assistant") {
			return nil, "", errors.New("ACI unsupported message role")
		}
	}
	plain, err := CanonicalValue(body)
	if err != nil {
		return nil, "", err
	}
	for index, message := range messages {
		content, err := Canonical(message["content"])
		if err != nil {
			return nil, "", errors.New("ACI message content missing")
		}
		var text string
		if json.Unmarshal(content, &text) == nil {
			content = []byte(text)
			// The server restores JSON-looking arrays as structured content. A
			// literal array-shaped string would change semantics and receipt hash.
			var parts []json.RawMessage
			if json.Unmarshal(content, &parts) == nil && strings.HasPrefix(strings.TrimSpace(text), "[") {
				return nil, "", errors.New("ACI v2 cannot preserve array-shaped text content")
			}
		} else if len(content) == 0 || content[0] != '[' {
			return nil, "", errors.New("ACI unsupported content shape")
		}
		aad, err := e.AAD(fmt.Sprintf("messages.%d.content", index), "", false)
		if err != nil {
			return nil, "", err
		}
		ciphertext, err := EncryptField(e.Server, content, aad)
		if err != nil {
			return nil, "", err
		}
		message["content"], err = json.Marshal(ciphertext)
		if err != nil {
			return nil, "", err
		}
	}
	body["messages"], err = CanonicalValue(messages)
	if err != nil {
		return nil, "", err
	}
	encrypted, err := CanonicalValue(body)
	return encrypted, Hash(plain), err
}

// DecryptStream runs only after receipt verification over the COMPLETE original
// SSE bytes. Buffering is bounded by the caller; no fabricated word-chunk stream.
// This prevents releasing unverified content or a success/usage terminal event.
func (e *Encryption) DecryptStream(raw []byte) ([]byte, string, error) {
	if len(raw) > MaxArtifactBytes {
		return nil, "", errors.New("ACI response too large")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), MaxArtifactBytes)
	var result bytes.Buffer
	chatID := ""
	done, finished, contentSeen := false, false, false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if done || !strings.HasPrefix(line, "data:") {
			return nil, "", errors.New("ACI malformed or trailing SSE")
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			done = true
			continue
		}
		var event map[string]json.RawMessage
		if err := Decode([]byte(data), &event); err != nil {
			return nil, "", err
		}
		if _, exists := event["error"]; exists {
			return nil, "", errors.New("ACI upstream stream error")
		}
		var id string
		if json.Unmarshal(event["id"], &id) != nil || id == "" || (chatID != "" && chatID != id) {
			return nil, "", errors.New("ACI stream identity changed")
		}
		chatID = id
		var choices []map[string]json.RawMessage
		if json.Unmarshal(event["choices"], &choices) != nil || len(choices) > 1 {
			return nil, "", errors.New("ACI unsupported choices")
		}
		for _, choice := range choices {
			var index int
			if rawIndex, exists := choice["index"]; exists {
				if json.Unmarshal(rawIndex, &index) != nil || index != 0 {
					return nil, "", errors.New("ACI invalid choice index")
				}
			}
			var delta map[string]json.RawMessage
			if json.Unmarshal(choice["delta"], &delta) != nil {
				return nil, "", errors.New("ACI invalid delta")
			}
			for field, value := range delta {
				if field == "role" {
					if string(value) != `"assistant"` {
						return nil, "", errors.New("ACI invalid response role")
					}
					continue
				}
				if field != "content" && field != "reasoning" && field != "reasoning_content" {
					return nil, "", errors.New("ACI response field has no encryption contract")
				}
				if finished {
					return nil, "", errors.New("ACI content after finish")
				}
				var ciphertext string
				if json.Unmarshal(value, &ciphertext) != nil {
					return nil, "", errors.New("ACI response field is not encrypted text")
				}
				if ciphertext == "" {
					continue
				}
				aad, err := e.AAD("choices.0.delta."+field, chatID, true)
				if err != nil {
					return nil, "", err
				}
				plaintext, err := DecryptField(e.Private, ciphertext, aad)
				if err != nil {
					return nil, "", err
				}
				if !utf8.Valid(plaintext) {
					return nil, "", errors.New("ACI decrypted content is not UTF-8")
				}
				delta[field], err = json.Marshal(string(plaintext))
				clear(plaintext)
				if err != nil {
					return nil, "", err
				}
				contentSeen = true
			}
			if reason, exists := choice["finish_reason"]; exists && string(reason) != "null" {
				if finished || (string(reason) != `"stop"` && string(reason) != `"length"`) {
					return nil, "", errors.New("ACI invalid finish reason")
				}
				finished = true
			}
			choice["delta"], _ = json.Marshal(delta)
		}
		event["choices"], _ = json.Marshal(choices)
		encoded, err := json.Marshal(event)
		if err != nil {
			return nil, "", err
		}
		result.WriteString("data: ")
		result.Write(encoded)
		result.WriteString("\n\n")
	}
	if scanner.Err() != nil || !done || !finished || !contentSeen {
		return nil, "", errors.New("ACI stream incomplete or empty")
	}
	result.WriteString("data: [DONE]\n\n")
	return result.Bytes(), chatID, nil
}

func validateChatControls(body map[string]json.RawMessage) error {
	for name, raw := range body {
		switch name {
		case "messages", "model":
			continue
		case "stream":
			if string(raw) != "true" {
				return errors.New("ACI adapter requires a real upstream stream")
			}
		case "stream_options", "thinking", "reasoning":
			var controls map[string]json.RawMessage
			if json.Unmarshal(raw, &controls) != nil || controls == nil {
				return errors.New("ACI invalid control object")
			}
			for key, value := range controls {
				valid := false
				switch {
				case name == "stream_options" && key == "include_usage", name == "thinking" && key == "enabled", name == "reasoning" && (key == "enabled" || key == "exclude"):
					valid = string(value) == "true" || string(value) == "false"
				case name == "thinking" && key == "type":
					valid = string(value) == `"enabled"` || string(value) == `"disabled"` || string(value) == `"adaptive"`
				case name == "reasoning" && key == "effort":
					for _, effort := range []string{`"none"`, `"minimal"`, `"low"`, `"medium"`, `"high"`, `"xhigh"`} {
						valid = valid || string(value) == effort
					}
				case (name == "thinking" && key == "budget_tokens") || (name == "reasoning" && key == "max_tokens"):
					var count int
					valid = json.Unmarshal(value, &count) == nil && count >= 0
				}
				if !valid {
					return errors.New("ACI control field has no safe cleartext contract")
				}
			}
		default:
			var number float64
			if string(raw) == "null" || json.Unmarshal(raw, &number) != nil {
				return errors.New("ACI sampling control must be numeric")
			}
		}
	}
	return nil
}
