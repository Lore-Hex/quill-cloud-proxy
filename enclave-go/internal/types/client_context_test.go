package types

import (
	"reflect"
	"strings"
	"testing"
)

func TestClientContextValidate(t *testing.T) {
	valid := ClientContext{
		V:              1,
		Source:         "tr",
		SDK:            "tr-py",
		SDKVersion:     "0.6.0+build.1",
		Lang:           "python",
		Runtime:        "cpython/3.12.1",
		OS:             "macos",
		Arch:           "arm64",
		TimeoutMS:      3_600_000,
		Attempt:        intPtr(99),
		PrevOutcome:    "transport_error",
		PrevErrorClass: "connect_timeout",
		PrevHost:       "apex",
		PrevElapsedMS:  intPtr(3_600_000),
		SinceFirstMS:   intPtr(0),
		Stream:         clientContextBoolPointer(false),
		FailoverUsed:   clientContextBoolPointer(true),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid context: %v", err)
	}
	if err := (*ClientContext)(nil).Validate(); err != nil {
		t.Fatalf("nil context: %v", err)
	}
	if err := (&ClientContext{}).Validate(); err != nil {
		t.Fatalf("empty context: %v", err)
	}

	tests := []struct {
		name  string
		field string
		set   func(*ClientContext)
	}{
		{name: "version missing", field: "v", set: func(c *ClientContext) { c.V = 0 }},
		{name: "version unknown", field: "v", set: func(c *ClientContext) { c.V = 2 }},
		{name: "source", field: "source", set: func(c *ClientContext) { c.Source = "sdk" }},
		{name: "sdk", field: "sdk", set: func(c *ClientContext) { c.SDK = "openai-ruby" }},
		{name: "sdk version grammar", field: "sdk_version", set: func(c *ClientContext) { c.SDKVersion = "1.2" }},
		{name: "sdk version length", field: "sdk_version", set: func(c *ClientContext) { c.SDKVersion = "1234.1234.1234+abcdefghijklmnopqr" }},
		{name: "lang", field: "lang", set: func(c *ClientContext) { c.Lang = "typescript" }},
		{name: "runtime", field: "runtime", set: func(c *ClientContext) { c.Runtime = "CPython/3.12.1" }},
		{name: "os", field: "os", set: func(c *ClientContext) { c.OS = "darwin" }},
		{name: "arch", field: "arch", set: func(c *ClientContext) { c.Arch = "amd64" }},
		{name: "timeout negative", field: "timeout_ms", set: func(c *ClientContext) { c.TimeoutMS = -1 }},
		{name: "timeout high", field: "timeout_ms", set: func(c *ClientContext) { c.TimeoutMS = 3_600_001 }},
		{name: "attempt negative", field: "attempt", set: func(c *ClientContext) { c.Attempt = intPtr(-1) }},
		{name: "attempt high", field: "attempt", set: func(c *ClientContext) { c.Attempt = intPtr(100) }},
		{name: "previous outcome", field: "prev_outcome", set: func(c *ClientContext) { c.PrevOutcome = "ok" }},
		{name: "previous error class", field: "prev_error_class", set: func(c *ClientContext) { c.PrevErrorClass = "socket" }},
		{name: "previous host", field: "prev_host", set: func(c *ClientContext) { c.PrevHost = "hostname" }},
		{name: "previous elapsed negative", field: "prev_elapsed_ms", set: func(c *ClientContext) { c.PrevElapsedMS = intPtr(-1) }},
		{name: "previous elapsed high", field: "prev_elapsed_ms", set: func(c *ClientContext) { c.PrevElapsedMS = intPtr(3_600_001) }},
		{name: "since first negative", field: "since_first_ms", set: func(c *ClientContext) { c.SinceFirstMS = intPtr(-1) }},
		{name: "since first high", field: "since_first_ms", set: func(c *ClientContext) { c.SinceFirstMS = intPtr(3_600_001) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := valid
			test.set(&context)
			err := context.Validate()
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("Validate() error = %v, want field %q", err, test.field)
			}
		})
	}
}

func TestClientContextAsBodyOmitsUnsetAndPreservesPointerZeros(t *testing.T) {
	context := &ClientContext{
		V:             1,
		Source:        "tr",
		SDK:           "tr-go",
		Attempt:       intPtr(0),
		PrevElapsedMS: intPtr(0),
		Stream:        clientContextBoolPointer(false),
		FailoverUsed:  clientContextBoolPointer(true),
	}
	want := map[string]any{
		"v":               1,
		"source":          "tr",
		"sdk":             "tr-go",
		"attempt":         0,
		"prev_elapsed_ms": 0,
		"stream":          false,
		"failover_used":   true,
	}
	if got := context.AsBody(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AsBody() = %#v, want %#v", got, want)
	}
	if got := (*ClientContext)(nil).AsBody(); len(got) != 0 {
		t.Fatalf("nil AsBody() = %#v, want empty", got)
	}
}

func clientContextBoolPointer(value bool) *bool { return &value }
