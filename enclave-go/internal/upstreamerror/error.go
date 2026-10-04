// Package upstreamerror carries provider failures without losing their wire body.
package upstreamerror

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Error struct {
	Status int
	Body   string
}

// Error omits provider payloads from logs; response rendering uses UpstreamResponse.
func (e *Error) Error() string                   { return fmt.Sprintf("llm/upstream: http %d: provider error", e.Status) }
func (e *Error) UpstreamResponse() (int, string) { return e.Status, e.Body }

// Open signals acceptance before reading tokens. Writers without this hook keep
// the buffered/non-streaming behavior, including pre-output fallback. The return
// value tells wrappers whether acceptance commits this response.
func Open(w io.Writer) bool {
	if w, ok := w.(interface{ UpstreamOpened() bool }); ok {
		return w.UpstreamOpened()
	}
	return false
}

type Detail struct {
	Status  int
	Message string
	Type    string
	Code    any
	Param   any
	Raw     string
	Parsed  bool
}

var httpPattern = regexp.MustCompile(`\bhttp ([45][0-9]{2}):\s*`)
var keyPattern = regexp.MustCompile(`(?i)\b(sk|rk)-[A-Za-z0-9_\-*]{4,}`)
var bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[^\s"'\\,}]+`)
var credentialPattern = regexp.MustCompile(`(?i)("(?:api[_-]?key|access[_-]?token|token|authorization|password|secret)"\s*:\s*")[^"\r\n]*(")`)

func sanitize(s string) string {
	var value any
	if json.Unmarshal([]byte(s), &value) == nil {
		changed := false
		var scrub func(any) any
		scrub = func(value any) any {
			switch value := value.(type) {
			case map[string]any:
				for key, child := range value {
					switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key)) {
					case "apikey", "accesstoken", "token", "authorization", "password", "secret":
						value[key] = "***"
						changed = true
					default:
						value[key] = scrub(child)
					}
				}
			case []any:
				for i, child := range value {
					value[i] = scrub(child)
				}
			case string:
				clean := sanitizeText(value)
				changed = changed || clean != value
				return clean
			}
			return value
		}
		value = scrub(value)
		if changed {
			encoded, _ := json.Marshal(value)
			return string(encoded)
		}
	}
	return sanitizeText(s)
}

func sanitizeText(s string) string {
	s = credentialPattern.ReplaceAllString(s, `${1}***${2}`)
	s = keyPattern.ReplaceAllString(s, "sk-***")
	return bearerPattern.ReplaceAllString(s, "Bearer ***")
}

func bounded(s string) string {
	if len(s) > 1200 {
		s = s[:1200]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func Parse(err error) Detail {
	d := Detail{Status: 502, Message: "provider error", Type: "provider_error"}
	if err == nil {
		return d
	}
	var response interface{ UpstreamResponse() (int, string) }
	var body string
	if errors.As(err, &response) {
		d.Status, body = response.UpstreamResponse()
	} else {
		s := err.Error()
		match := httpPattern.FindStringSubmatchIndex(s)
		if match == nil {
			return d
		}
		d.Status, _ = strconv.Atoi(s[match[2]:match[3]])
		body = s[match[1]:]
	}
	if d.Status < 400 || d.Status >= 600 {
		return Detail{Status: 502, Message: "provider error", Type: "provider_error"}
	}
	body = strings.TrimSpace(body)
	d.Raw = bounded(sanitize(body))
	var obj map[string]any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&obj) == nil && obj != nil {
		fields := obj
		if response, ok := obj["response"].(map[string]any); ok {
			obj = response
			fields = obj
		}
		if nested, ok := obj["error"].(map[string]any); ok {
			fields = nested
		}
		for _, k := range []string{"message", "msg", "detail", "error"} {
			if value, ok := fields[k].(string); ok && strings.TrimSpace(value) != "" {
				d.Message, d.Parsed = bounded(sanitize(value)), true
				break
			}
		}
		if value, ok := fields["type"].(string); ok && value != "" && value != "error" {
			d.Type = bounded(sanitize(value))
		} else if value, ok := fields["status"].(string); ok && value != "" {
			// Google's symbolic status fills type; keep its numeric code intact.
			d.Type = bounded(sanitize(value))
		}
		d.Code = scalar(fields["code"])
		d.Param = scalar(fields["param"])
	} else if d.Raw != "" {
		d.Message = d.Raw
	}
	if !d.Parsed && d.Message == "provider error" && d.Raw != "" {
		d.Message = d.Raw
	}
	return d
}

func scalar(v any) any {
	switch v := v.(type) {
	case string:
		return bounded(sanitize(v))
	case json.Number:
		return v
	default:
		return nil
	}
}

// FromEvent recognizes structured SSE failures; status-less events use 502.
func FromEvent(payload string) error {
	var obj map[string]any
	if json.Unmarshal([]byte(payload), &obj) != nil {
		return nil
	}
	if response, ok := obj["response"].(map[string]any); ok && obj["type"] == "response.failed" {
		obj = response
	}
	value, ok := obj["error"]
	if !ok && obj["type"] == "error" {
		value, ok = obj, true
	}
	if !ok || value == nil {
		return nil
	}
	fields, _ := value.(map[string]any)
	status := 502
	for _, source := range []map[string]any{obj, fields} {
		for _, key := range []string{"status", "code"} {
			if n, ok := source[key].(float64); ok && n >= 400 && n < 600 && n == float64(int(n)) {
				status = int(n)
			}
		}
	}
	if status == 502 {
		switch fields["type"] {
		case "invalid_request_error":
			status = 400
		case "authentication_error":
			status = 401
		case "permission_error":
			status = 403
		case "rate_limit_error":
			status = 429
		case "overloaded_error":
			status = 529
		}
	}
	return &Error{Status: status, Body: payload}
}
