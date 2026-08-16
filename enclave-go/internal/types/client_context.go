package types

import (
	"fmt"
	"regexp"
)

var (
	clientSDKVersionPattern = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([-+][0-9A-Za-z.]{0,20})?$`)
	clientRuntimePattern    = regexp.MustCompile(`^[a-z]{1,10}/[0-9A-Za-z.+-]{1,24}$`)
)

type ClientContext struct {
	V              int
	Source         string
	SDK            string
	SDKVersion     string
	Lang           string
	Runtime        string
	OS             string
	Arch           string
	TimeoutMS      int
	Attempt        *int
	PrevOutcome    string
	PrevErrorClass string
	PrevHost       string
	PrevElapsedMS  *int
	SinceFirstMS   *int
	Stream         *bool
	FailoverUsed   *bool
}

func (c *ClientContext) Validate() error {
	if c == nil {
		return nil
	}
	if c.V != 0 || c.hasFields() {
		if c.V != 1 {
			return clientContextFieldError("v")
		}
	}
	if c.Source != "" && !oneOf(c.Source, "tr", "stainless", "none") {
		return clientContextFieldError("source")
	}
	if c.SDK != "" && !oneOf(c.SDK,
		"tr-py", "tr-js", "tr-go", "tr-rust", "tr-java", "tr-swift",
		"openai-python", "openai-js", "openai-go", "openai-java", "openai-other",
		"anthropic-python", "anthropic-js", "anthropic-go", "anthropic-java", "anthropic-other",
		"other",
	) {
		return clientContextFieldError("sdk")
	}
	if c.SDKVersion != "" && (len(c.SDKVersion) > 32 || !clientSDKVersionPattern.MatchString(c.SDKVersion)) {
		return clientContextFieldError("sdk_version")
	}
	if c.Lang != "" && !oneOf(c.Lang,
		"python", "js", "go", "rust", "java", "swift", "kotlin", "ruby", "csharp", "php", "dart", "other",
	) {
		return clientContextFieldError("lang")
	}
	if c.Runtime != "" && !clientRuntimePattern.MatchString(c.Runtime) {
		return clientContextFieldError("runtime")
	}
	if c.OS != "" && !oneOf(c.OS, "linux", "macos", "windows", "ios", "android", "freebsd", "other") {
		return clientContextFieldError("os")
	}
	if c.Arch != "" && !oneOf(c.Arch, "x64", "x32", "arm", "arm64", "wasm", "other") {
		return clientContextFieldError("arch")
	}
	if c.TimeoutMS < 0 || c.TimeoutMS > 3_600_000 {
		return clientContextFieldError("timeout_ms")
	}
	if c.Attempt != nil && (*c.Attempt < 0 || *c.Attempt > 99) {
		return clientContextFieldError("attempt")
	}
	if c.PrevOutcome != "" && !oneOf(c.PrevOutcome, "none", "http_error", "transport_error", "timeout", "stream_broken") {
		return clientContextFieldError("prev_outcome")
	}
	if c.PrevErrorClass != "" && !oneOf(c.PrevErrorClass,
		"none", "dns", "tls", "connect_refused", "connect_timeout", "connect_error", "read_timeout", "write_timeout",
		"pool_timeout", "protocol_error", "reset", "io_error", "proxy_error", "stream_stalled", "unknown",
	) {
		return clientContextFieldError("prev_error_class")
	}
	if c.PrevHost != "" && !oneOf(c.PrevHost,
		"none", "apex", "ally", "uptime", "us_central1", "us_east4", "europe_west4", "control", "custom",
	) {
		return clientContextFieldError("prev_host")
	}
	if c.PrevElapsedMS != nil && (*c.PrevElapsedMS < 0 || *c.PrevElapsedMS > 3_600_000) {
		return clientContextFieldError("prev_elapsed_ms")
	}
	if c.SinceFirstMS != nil && (*c.SinceFirstMS < 0 || *c.SinceFirstMS > 3_600_000) {
		return clientContextFieldError("since_first_ms")
	}
	return nil
}

func (c *ClientContext) AsBody() map[string]any {
	body := make(map[string]any)
	if c == nil {
		return body
	}
	if c.V != 0 {
		body["v"] = c.V
	}
	if c.Source != "" {
		body["source"] = c.Source
	}
	if c.SDK != "" {
		body["sdk"] = c.SDK
	}
	if c.SDKVersion != "" {
		body["sdk_version"] = c.SDKVersion
	}
	if c.Lang != "" {
		body["lang"] = c.Lang
	}
	if c.Runtime != "" {
		body["runtime"] = c.Runtime
	}
	if c.OS != "" {
		body["os"] = c.OS
	}
	if c.Arch != "" {
		body["arch"] = c.Arch
	}
	if c.TimeoutMS != 0 {
		body["timeout_ms"] = c.TimeoutMS
	}
	if c.Attempt != nil {
		body["attempt"] = *c.Attempt
	}
	if c.PrevOutcome != "" {
		body["prev_outcome"] = c.PrevOutcome
	}
	if c.PrevErrorClass != "" {
		body["prev_error_class"] = c.PrevErrorClass
	}
	if c.PrevHost != "" {
		body["prev_host"] = c.PrevHost
	}
	if c.PrevElapsedMS != nil {
		body["prev_elapsed_ms"] = *c.PrevElapsedMS
	}
	if c.SinceFirstMS != nil {
		body["since_first_ms"] = *c.SinceFirstMS
	}
	if c.Stream != nil {
		body["stream"] = *c.Stream
	}
	if c.FailoverUsed != nil {
		body["failover_used"] = *c.FailoverUsed
	}
	return body
}

func (c *ClientContext) hasFields() bool {
	return c.Source != "" || c.SDK != "" || c.SDKVersion != "" || c.Lang != "" || c.Runtime != "" ||
		c.OS != "" || c.Arch != "" || c.TimeoutMS != 0 || c.Attempt != nil || c.PrevOutcome != "" ||
		c.PrevErrorClass != "" || c.PrevHost != "" || c.PrevElapsedMS != nil || c.SinceFirstMS != nil ||
		c.Stream != nil || c.FailoverUsed != nil
}

func clientContextFieldError(field string) error {
	return fmt.Errorf("invalid client context field %s", field)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
