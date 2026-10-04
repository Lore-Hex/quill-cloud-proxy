package upstreamerror

import (
	"errors"
	"testing"
)

func TestFromEventUndecodableChunks(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		failure       bool
	}{
		{"malformed content", `{"choices":[`, false},
		{"malformed error", `{"error" : {`, true},
		{"trailing content", `{"choices":[]} {"choices":[]}`, false},
		{"trailing junk", `{"choices":[]} junk`, false},
		{"trailing error", `{"choices":[]} {"error":{"message":"refused"}}`, true},
		{"malformed error type", `{"type" : "error",`, true},
		{"malformed response failed", `{"type" : "response.failed",`, true},
		{"error value cut off at the end", `broken "error":`, true},
		{"error value cut off before whitespace", "{\"error\": \t", true},
		{"non-object error type", `broken "type":"error"`, true},
		{"unrelated type", `{"type":"response.failed.other",`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := FromEvent(tc.payload)
			if !tc.failure {
				if err != nil {
					t.Fatalf("non-error chunk failed the stream: %v", err)
				}
				return
			}
			var upstream *Error
			if !errors.As(err, &upstream) || upstream.Status != 502 || upstream.Body != tc.payload {
				t.Fatalf("error report lost: %#v", err)
			}
		})
	}
}

func TestFromEventMalformedNullError(t *testing.T) {
	for _, tc := range []struct {
		payload string
		failure bool
	}{
		{`{"error":null,"choices":[broken`, false},
		{`{"error": null,"choices":[broken`, false},
		{`{"error":{"message":"x"},"choices":[broken`, true},
	} {
		if err := FromEvent(tc.payload); (err != nil) != tc.failure {
			t.Errorf("payload=%s err=%v want failure=%t", tc.payload, err, tc.failure)
		}
	}
}
