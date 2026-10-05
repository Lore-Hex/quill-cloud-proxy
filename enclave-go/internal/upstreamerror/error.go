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
	"unicode"
	"unicode/utf8"

	"github.com/aws/smithy-go"
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
var providerTokenPattern = regexp.MustCompile(`\b(?:AIza[A-Za-z0-9_-]{35}|ya29\.[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`)
var headerCredentialPattern = regexp.MustCompile(`(?i)(\b(?:x-api-key|x-goog-api-key|api-key|authorization|x-auth-token|x-access-token)\s*[:=]\s*)[^\s"'\\,;}]+`)
var bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[^\s"'\\,}]+`)
var credentialPattern = regexp.MustCompile(`(?i)("(?:(?:x[_-]?(?:goog[_-]?)?)?api[_-]?key|(?:x[_-]?)?access[_-]?token|x[_-]?auth[_-]?token|token|(?:proxy[_-]?)?authorization|password|secret|x[_-]?amz[_-]?security[_-]?token)"\s*:\s*")[^"\r\n]*(")`)

func sanitize(s string, secrets ...string) string {
	var value any
	decoder := json.NewDecoder(strings.NewReader(s))
	decoder.UseNumber()
	var trailing any
	if decoder.Decode(&value) == nil && decoder.Decode(&trailing) == io.EOF {
		changed := false
		var scrub func(any) any
		scrub = func(value any) any {
			switch value := value.(type) {
			case map[string]any:
				clean := make(map[string]any, len(value))
				for key, child := range value {
					cleanKey := sanitizeText(key, secrets...)
					changed = changed || cleanKey != key
					if IsCredentialName(key) {
						clean[cleanKey] = "***"
						changed = true
					} else {
						clean[cleanKey] = scrub(child)
					}
				}
				return clean
			case json.Number:
				clean := sanitizeText(string(value), secrets...)
				if clean != string(value) {
					changed = true
					return clean
				}
			case []any:
				for i, child := range value {
					value[i] = scrub(child)
				}
			case string:
				clean := sanitizeText(value, secrets...)
				changed = changed || clean != value
				return clean
			}
			return value
		}
		value = scrub(value)
		// The raw text can hold what decoding discards (a duplicate key keeps
		// only its last value), so it is returned only when a text pass over it
		// finds nothing either; otherwise emit the scrubbed decoded value.
		if normalized := normalizeJSONEscapes(s); !changed && sanitizeText(normalized, secrets...) == normalized {
			return s
		}
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}
	return sanitizeText(normalizeJSONEscapes(s), secrets...)
}

// Decode escapes even when a truncated/malformed body cannot be parsed. Match
// surrogate pairs together so they normalize to the same rune as credentials.
var jsonEscapePattern = regexp.MustCompile(`\\u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\(?:u[0-9a-fA-F]{4}|["\\/bfnrt])`)

func normalizeJSONEscapes(s string) string {
	return jsonEscapePattern.ReplaceAllStringFunc(s, func(escape string) string {
		var decoded string
		_ = json.Unmarshal([]byte(`"`+escape+`"`), &decoded)
		return decoded
	})
}

func sanitizeText(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "***")
			encoded, _ := json.Marshal(secret)
			s = strings.ReplaceAll(s, string(encoded[1:len(encoded)-1]), "***")
		}
	}
	s = credentialPattern.ReplaceAllString(s, `${1}***${2}`)
	s = bearerPattern.ReplaceAllString(s, "Bearer ***")
	s = headerCredentialPattern.ReplaceAllString(s, `${1}***`)
	s = keyPattern.ReplaceAllString(s, "sk-***")
	s = providerTokenPattern.ReplaceAllString(s, "***")
	return s
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

// responseBody is shared with credential redaction so SDK errors are scrubbed
// before fallback tracking retains them, just like HTTP provider bodies.
func responseBody(err error) (int, string, bool) {
	var response interface{ UpstreamResponse() (int, string) }
	if errors.As(err, &response) {
		status, body := response.UpstreamResponse()
		return status, body, true
	}
	var httpStatus interface{ HTTPStatusCode() int }
	hasHTTPStatus := errors.As(err, &httpStatus)
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		// ModelStreamErrorException, ModelErrorException and unknown codes use 502.
		status := 502
		switch apiError.ErrorCode() {
		case "ValidationException":
			status = 400
		case "AccessDeniedException":
			status = 403
		case "ResourceNotFoundException":
			status = 404
		case "ModelTimeoutException":
			status = 408
		case "ThrottlingException", "ServiceQuotaExceededException":
			status = 429
		case "InternalServerException":
			status = 500
		case "ServiceUnavailableException", "ModelNotReadyException":
			status = 503
		}
		if hasHTTPStatus {
			status = httpStatus.HTTPStatusCode()
		}
		encoded, _ := json.Marshal(map[string]any{"error": map[string]string{
			"code": apiError.ErrorCode(), "message": apiError.ErrorMessage(),
		}})
		return status, string(encoded), true
	}
	if hasHTTPStatus {
		return httpStatus.HTTPStatusCode(), err.Error(), true
	}
	s := err.Error()
	match := httpPattern.FindStringSubmatchIndex(s)
	if match == nil {
		return 0, "", false
	}
	status, _ := strconv.Atoi(s[match[2]:match[3]])
	return status, s[match[1]:], true
}

func Parse(err error) Detail {
	d := Detail{Status: 502, Message: "provider error", Type: "provider_error"}
	if err == nil {
		return d
	}
	status, body, ok := responseBody(err)
	if !ok {
		return d
	}
	d.Status = status
	if d.Status < 400 || d.Status >= 600 {
		return Detail{Status: 502, Message: "provider error", Type: "provider_error"}
	}
	body = strings.TrimSpace(body)
	d.Raw = bounded(sanitize(body))
	var obj map[string]any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&obj) == nil && obj != nil {
		if response, ok := obj["response"].(map[string]any); ok {
			obj = response
		}
		obj = errorObject(obj)
		fields := obj
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
		if len(v) > 1200 {
			return nil
		}
		return v
	default:
		return nil
	}
}

// An error key with any value except null, or with its value cut off at the
// end of the payload (an error object split across data lines), is a report.
var errorEventPattern = regexp.MustCompile(`"error"\s*:\s*(?:$|[^\sn])|"type"\s*:\s*"(?:error|response\.failed)"`)
var jsonStringPattern = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

func looksLikeError(payload string) bool {
	// Preserve detection of escaped error keys/type values even when the rest
	// of the report is malformed and cannot be decoded as an object.
	if strings.Contains(payload, `\u`) {
		payload = jsonStringPattern.ReplaceAllStringFunc(payload, func(token string) string {
			var value string
			if json.Unmarshal([]byte(token), &value) == nil {
				encoded, _ := json.Marshal(value)
				return string(encoded)
			}
			return token
		})
	}
	return errorEventPattern.MatchString(payload)
}

// FromEvent recognizes structured SSE failures; status-less events use 502.
func FromEvent(payload string) error {
	var obj map[string]any
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&obj); err != nil {
		// Leave malformed content to the provider's existing skip/fail policy.
		if looksLikeError(payload) {
			return &Error{Status: 502, Body: payload}
		}
		return nil
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		if looksLikeError(payload) {
			return &Error{Status: 502, Body: payload}
		}
		return nil
	}
	failed := obj["type"] == "error" || obj["type"] == "response.failed"
	if response, ok := obj["response"].(map[string]any); ok && obj["type"] == "response.failed" {
		obj = response
	}
	root := obj
	obj = errorObject(obj)
	value, ok := obj["error"]
	if !ok && obj["type"] == "error" {
		value, ok = obj, true
	}
	if (!ok || value == nil) && !failed {
		return nil
	}
	fields, _ := value.(map[string]any)
	status := 502
	for _, source := range []map[string]any{root, obj, fields} {
		for _, key := range []string{"status", "code"} {
			if number, ok := source[key].(json.Number); ok {
				if n, err := number.Float64(); err == nil && n >= 400 && n < 600 && n == float64(int(n)) {
					status = int(n)
				}
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

// Inspect errors before provider-specific typed decoding can reject unrelated
// fields (for example an overflowing token count). Null errors are ordinary data.
func errorObject(obj map[string]any) map[string]any {
	if obj["error"] != nil {
		return obj
	}
	choices, _ := obj["choices"].([]any)
	for _, value := range choices {
		choice, _ := value.(map[string]any)
		if choice["error"] != nil {
			return choice
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta["error"] != nil {
			return delta
		}
	}
	return obj
}

// CheckEvent checks a provider payload and failures declared by the SSE name.
// Line readers pass an empty name and keep their own framing and malformed-data
// policy. Complete-event readers can join data lines before checking.
func CheckEvent(name, data string) error {
	if err := FromEvent(data); err != nil {
		return err
	}
	if name == "error" || name == "response.failed" {
		return &Error{Status: 502, Body: data}
	}
	return nil
}

// CheckLine preserves per-line decoding while recognizing error tokens split
// across scalar or undecodable payloads. Readers clear tail at event boundaries.
// Only the new payload and at most 64 preceding significant bytes are inspected.
func CheckLine(payload string, tail *string) error {
	if err := CheckEvent("", payload); err != nil {
		return err
	}
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return nil
	}
	if (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(payload)) {
		*tail = ""
		return nil
	}
	joined := *tail + "\n" + payload
	if *tail != "" && looksLikeError(joined) {
		return &Error{Status: 502, Body: joined}
	}
	// Whitespace between JSON tokens is insignificant and the pattern allows
	// any amount, so collapse each run before keeping the tail: padding (before
	// or after a colon) can then never push a key out of the window.
	joined = strings.Join(strings.FieldsFunc(joined, unicode.IsSpace), " ")
	*tail = strings.Clone(joined[max(0, len(joined)-64):])
	return nil
}
