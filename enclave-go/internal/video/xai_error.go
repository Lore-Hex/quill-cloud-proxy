package video

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
)

// xaiErrorBodyLimit bounds how much of an xAI error body is read. The body is
// parsed only to pick allowlisted symbols; it is never stored or logged.
const xaiErrorBodyLimit = 16 * 1024

// xaiErrorCodes maps the symbols xAI uses in error bodies to our own fixed
// labels. xAI's HTTP errors are {"code": "<status description>", "error":
// "<message>"}, where code is the gRPC canonical status description (for
// example "Client specified an invalid argument"). Its video job errors are
// documented as error.code in {invalid_argument, permission_denied,
// failed_precondition, service_unavailable, internal_error}. Anything else,
// including a bare status number, is dropped.
var xaiErrorCodes = map[string]string{
	"Client specified an invalid argument":                                   "invalid_argument",
	"Some requested entity was not found":                                    "not_found",
	"Some entity that we attempted to create already exists":                 "already_exists",
	"The caller does not have permission to execute the specified operation": "permission_denied",
	"Some resource has been exhausted":                                       "resource_exhausted",
	"The system is not in a state required for the operation's execution":    "failed_precondition",
	"Operation was attempted past the valid range":                           "out_of_range",
	"Operation is not implemented or not supported":                          "unimplemented",
	"Internal error":                                             "internal",
	"The service is currently unavailable":                       "unavailable",
	"The request does not have valid authentication credentials": "unauthenticated",
	"Deadline expired before operation could complete":           "deadline_exceeded",
	"invalid_argument":                                           "invalid_argument",
	"permission_denied":                                          "permission_denied",
	"failed_precondition":                                        "failed_precondition",
	"service_unavailable":                                        "service_unavailable",
	"internal_error":                                             "internal_error",
	"not_found":                                                  "not_found",
	"resource_exhausted":                                         "resource_exhausted",
	"unauthenticated":                                            "unauthenticated",
}

// xaiVideoFields are the field names of the xAI video generation request
// (POST /v1/videos/generations). A field is reported only when the error names
// it; no other word of the error message is ever kept.
var xaiVideoFields = map[string]bool{
	"model": true, "prompt": true, "duration": true, "seconds": true,
	"aspect_ratio": true, "resolution": true, "image": true, "image_url": true,
	"url": true, "file_id": true, "reference_images": true, "keyframes": true,
	"timestamp_s": true, "reference_audios": true, "voice_id": true,
	"output": true, "upload_url": true, "storage_options": true, "user": true,
}

// classifyXAIError reads at most xaiErrorBodyLimit bytes of an xAI error body
// and returns only an allowlisted code label and the allowlisted request field
// names the error mentions (sorted, unique). It never returns provider text.
func classifyXAIError(body io.Reader) (code string, fields []string) {
	if body == nil {
		return "", nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, xaiErrorBodyLimit))
	if err != nil || len(raw) == 0 {
		return "", nil
	}
	var parsed map[string]json.RawMessage
	if json.Unmarshal(raw, &parsed) != nil {
		return "", nil
	}
	var messages []string
	var params []string
	readStrings := func(object map[string]json.RawMessage) {
		var value string
		if json.Unmarshal(object["code"], &value) == nil && code == "" {
			code = xaiErrorCodes[strings.TrimSpace(value)]
		}
		if json.Unmarshal(object["type"], &value) == nil && code == "" {
			code = xaiErrorCodes[strings.TrimSpace(value)]
		}
		for _, key := range []string{"error", "message"} {
			if json.Unmarshal(object[key], &value) == nil {
				messages = append(messages, value)
			}
		}
		if json.Unmarshal(object["param"], &value) == nil {
			params = append(params, value)
		}
	}
	readStrings(parsed)
	// The documented job error shape nests {code, message} under "error".
	var nested map[string]json.RawMessage
	if json.Unmarshal(parsed["error"], &nested) == nil {
		readStrings(nested)
	}
	seen := map[string]bool{}
	for _, param := range params {
		if name := strings.TrimSpace(param); xaiVideoFields[name] {
			seen[name] = true
		}
	}
	for _, message := range messages {
		for _, token := range strings.FieldsFunc(message, notFieldNameRune) {
			if xaiVideoFields[token] {
				seen[token] = true
			}
		}
	}
	for name := range seen {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return code, fields
}

func notFieldNameRune(r rune) bool {
	return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
}

// requireXAISuccess is requireProviderSuccess plus the sanitized xAI error
// classification on a 4xx/5xx.
func requireXAISuccess(provider string, resp *http.Response) error {
	err := requireProviderSuccess(provider, resp)
	if err == nil {
		return nil
	}
	if httpErr, ok := err.(*HTTPError); ok {
		httpErr.Code, httpErr.Fields = classifyXAIError(resp.Body)
	}
	return err
}
