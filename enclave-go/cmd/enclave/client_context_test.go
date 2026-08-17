package main

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseClientContextUserAgents(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want map[string]any
	}{
		{name: "OpenAI Python", ua: "OpenAI/Python 2.46.0", want: clientBody("openai-python", "2.46.0", "")},
		{name: "OpenAI JS", ua: "OpenAI/JS 5.8.2", want: clientBody("openai-js", "5.8.2", "")},
		{name: "Anthropic Python", ua: "Anthropic/Python 0.117.0", want: clientBody("anthropic-python", "0.117.0", "")},
		{name: "Anthropic JS", ua: "Anthropic/JS 0.115.0", want: clientBody("anthropic-js", "0.115.0", "")},
		{name: "OpenAI Go slash version", ua: "OpenAI/Go/1.4.2", want: clientBody("openai-go", "1.4.2", "")},
		{name: "Anthropic Java", ua: "Anthropic/Java 2.3.4", want: clientBody("anthropic-java", "2.3.4", "")},
		{name: "unknown vendor language", ua: "OpenAI/Ruby 1.2.3", want: clientBody("openai-other", "1.2.3", "")},
		{name: "TrustedRouter Python", ua: "trusted-router-py/0.6.0 python/3.12.1 platform/macos", want: clientBody("tr-py", "0.6.0", "python/3.12.1")},
		{name: "TrustedRouter Go", ua: "trusted-router-go/1.2.3 go/1.24.2", want: clientBody("tr-go", "1.2.3", "go/1.24.2")},
		// The exact shapes the six SDKs send today (userAgent()/Transport.java/
		// transport.rs/Constants.swift at origin/main), so a UA change in any
		// SDK that stops classifying shows up here first.
		{name: "real py", ua: "trusted-router-py/0.5.0 python/3.12.1 httpx/0.27.0 Darwin", want: clientBody("tr-py", "0.5.0", "python/3.12.1")},
		{name: "real js", ua: "trusted-router-js/0.4.0 node/22.4.0 darwin", want: clientBody("tr-js", "0.4.0", "node/22.4.0")},
		{name: "real js browser", ua: "trusted-router-js/0.4.0 browser web", want: clientBody("tr-js", "0.4.0", "")},
		{name: "real go", ua: "trusted-router-go/0.3.0 go/go1.24.2 linux", want: clientBody("tr-go", "0.3.0", "go/go1.24.2")},
		{name: "real java", ua: "trusted-router-java/0.2.0 java/17.0.2 Linux", want: clientBody("tr-java", "0.2.0", "java/17.0.2")},
		{name: "real rust", ua: "trusted-router-rust/0.3.0", want: clientBody("tr-rust", "0.3.0", "")},
		{name: "real swift", ua: "trusted-router-swift/1.0.0 (macOS 14.5)", want: clientBody("tr-swift", "1.0.0", "")},
		{name: "garbage", ua: "curl/8.7.1", want: clientBody("other", "", "")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, dropped := parseClientContext(clientContextHeaders{userAgent: test.ua})
			if len(dropped) != 0 {
				t.Fatalf("dropped = %#v", dropped)
			}
			if got == nil || !reflect.DeepEqual(got.AsBody(), test.want) {
				t.Fatalf("context = %#v, want %#v", got, test.want)
			}
		})
	}

	got, dropped := parseClientContext(clientContextHeaders{userAgent: strings.Repeat("u", 300)})
	if got != nil || !reflect.DeepEqual(dropped, []string{"user_agent_too_long"}) {
		t.Fatalf("overlong UA = (%#v, %#v)", got, dropped)
	}
}

func TestParseClientContextStainless(t *testing.T) {
	full := clientContextHeaders{
		stainlessLang:           "Python",
		stainlessRuntime:        "CPython",
		stainlessRuntimeVersion: "3.12.1",
		stainlessOS:             "MacOS",
		stainlessArch:           "ARM64",
		stainlessRetryCount:     "2",
		stainlessTimeout:        "120",
		stainlessReadTimeout:    "30",
	}
	got, dropped := parseClientContext(full)
	if len(dropped) != 0 {
		t.Fatalf("dropped = %#v", dropped)
	}
	want := map[string]any{
		"v":          1,
		"source":     "stainless",
		"lang":       "python",
		"runtime":    "cpython/3.12.1",
		"os":         "macos",
		"arch":       "arm64",
		"attempt":    2,
		"timeout_ms": 120000,
	}
	if got == nil || !reflect.DeepEqual(got.AsBody(), want) {
		t.Fatalf("context = %#v, want %#v", got, want)
	}

	tests := []struct {
		name        string
		raw         clientContextHeaders
		want        map[string]any
		wantDropped []string
	}{
		{
			name: "browser runtime",
			raw:  clientContextHeaders{stainlessRuntime: "browser:chrome", stainlessRuntimeVersion: "v133.0"},
			want: map[string]any{"v": 1, "source": "stainless", "runtime": "browser/133.0"},
		},
		{
			name: "unknown enums",
			raw:  clientContextHeaders{stainlessLang: "typescript", stainlessOS: "Solaris", stainlessArch: "riscv64"},
			want: map[string]any{"v": 1, "source": "stainless", "lang": "other", "os": "other", "arch": "other"},
		},
		{
			name:        "retry non-number",
			raw:         clientContextHeaders{stainlessRetryCount: "abc"},
			wantDropped: []string{"stainless_retry_count"},
		},
		{
			name:        "retry over bound",
			raw:         clientContextHeaders{stainlessRetryCount: "100"},
			wantDropped: []string{"stainless_retry_count"},
		},
		{
			name: "read timeout fallback",
			raw:  clientContextHeaders{stainlessReadTimeout: "0.001"},
			want: map[string]any{"v": 1, "source": "stainless", "timeout_ms": 1},
		},
		{
			name:        "timeout malformed",
			raw:         clientContextHeaders{stainlessTimeout: "abc"},
			wantDropped: []string{"stainless_timeout"},
		},
		{
			name:        "invalid preferred timeout uses read timeout",
			raw:         clientContextHeaders{stainlessTimeout: "abc", stainlessReadTimeout: "12.5"},
			want:        map[string]any{"v": 1, "source": "stainless", "timeout_ms": 12500},
			wantDropped: []string{"stainless_timeout"},
		},
		{
			name:        "value too long",
			raw:         clientContextHeaders{stainlessLang: strings.Repeat("p", 65)},
			wantDropped: []string{"stainless_value_too_long"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context, reasons := parseClientContext(test.raw)
			if !slices.Equal(reasons, test.wantDropped) {
				t.Fatalf("dropped = %#v, want %#v", reasons, test.wantDropped)
			}
			if test.want == nil {
				if context != nil {
					t.Fatalf("context = %#v, want nil", context)
				}
				return
			}
			if context == nil || !reflect.DeepEqual(context.AsBody(), test.want) {
				t.Fatalf("context = %#v, want %#v", context, test.want)
			}
		})
	}
}

func TestParseClientContextTRHeader(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		want        map[string]any
		wantDropped []string
	}{
		{
			name:   "first attempt",
			header: "v=1;a=0;s=1",
			want:   map[string]any{"v": 1, "source": "tr", "attempt": 0, "stream": true},
		},
		{
			name:   "retry",
			header: "v=1;a=1;po=transport_error;pc=connect_timeout;ph=apex;pm=10012;sm=10530;s=1;fo=1",
			want: map[string]any{
				"v": 1, "source": "tr", "attempt": 1, "prev_outcome": "transport_error",
				"prev_error_class": "connect_timeout", "prev_host": "apex", "prev_elapsed_ms": 10012,
				"since_first_ms": 10530, "stream": true, "failover_used": true,
			},
		},
		{name: "unknown key", header: "v=1;zz=1", wantDropped: []string{"x_tr_client_grammar"}},
		{name: "duplicate key", header: "v=1;a=0;a=1", wantDropped: []string{"x_tr_client_grammar"}},
		{name: "uppercase value", header: "v=1;po=HTTP_ERROR", wantDropped: []string{"x_tr_client_grammar"}},
		{name: "wrong version", header: "v=2;a=0", wantDropped: []string{"x_tr_client_grammar"}},
		{name: "overlong", header: strings.Repeat("x", 161), wantDropped: []string{"x_tr_client_too_long"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context, reasons := parseClientContext(clientContextHeaders{trClient: test.header})
			if !slices.Equal(reasons, test.wantDropped) {
				t.Fatalf("dropped = %#v, want %#v", reasons, test.wantDropped)
			}
			if test.want == nil {
				if context != nil {
					t.Fatalf("context = %#v, want nil", context)
				}
				return
			}
			if context == nil || !reflect.DeepEqual(context.AsBody(), test.want) {
				t.Fatalf("context = %#v, want %#v", context, test.want)
			}
		})
	}
}

func TestParseClientContextSourceAndAttemptPrecedence(t *testing.T) {
	context, dropped := parseClientContext(clientContextHeaders{
		userAgent:           "OpenAI/Python 2.46.0",
		stainlessLang:       "python",
		stainlessRetryCount: "7",
		trClient:            "v=1;a=1;s=0",
	})
	if len(dropped) != 0 {
		t.Fatalf("dropped = %#v", dropped)
	}
	want := map[string]any{
		"v": 1, "source": "tr", "sdk": "openai-python", "sdk_version": "2.46.0",
		"lang": "python", "attempt": 1, "stream": false,
	}
	if context == nil || !reflect.DeepEqual(context.AsBody(), want) {
		t.Fatalf("context = %#v, want %#v", context, want)
	}

	context, dropped = parseClientContext(clientContextHeaders{
		stainlessLang: "go",
		trClient:      "v=1;zz=1",
	})
	if context == nil || context.Source != "stainless" || !reflect.DeepEqual(dropped, []string{"x_tr_client_grammar"}) {
		t.Fatalf("malformed TR fallback = (%#v, %#v)", context, dropped)
	}

	context, dropped = parseClientContext(clientContextHeaders{})
	if context != nil || len(dropped) != 0 {
		t.Fatalf("empty = (%#v, %#v)", context, dropped)
	}
}

func clientBody(sdk, version, runtime string) map[string]any {
	body := map[string]any{"v": 1, "source": "none", "sdk": sdk}
	if version != "" {
		body["sdk_version"] = version
	}
	if runtime != "" {
		body["runtime"] = runtime
	}
	return body
}
