package main

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	maxClientUserAgentBytes      = 256
	maxClientStainlessValueBytes = 64
	maxTRClientHeaderBytes       = 160
)

var (
	clientContextSemverPattern  = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([-+][0-9A-Za-z.]{0,20})?$`)
	clientContextRuntimePattern = regexp.MustCompile(`^[a-z]{1,10}/[0-9A-Za-z.+-]{1,24}$`)
	trustedRouterUAPattern      = regexp.MustCompile(`^trusted-router-(py|js|go|rust|java|swift)/([^ ]+)( ([a-z]+)/([0-9A-Za-z.+-]{1,24}))?`)
	vendorUAPattern             = regexp.MustCompile(`(?i)^(OpenAI|Anthropic)/([A-Za-z]+)\b[ /]?([^ ]+)?`)
	trClientValuePattern        = regexp.MustCompile(`^[a-z0-9_]{1,24}$`)
)

type clientContextHeaders struct {
	userAgent               string
	stainlessLang           string
	stainlessRuntime        string
	stainlessRuntimeVersion string
	stainlessOS             string
	stainlessArch           string
	stainlessRetryCount     string
	stainlessTimeout        string
	stainlessReadTimeout    string
	trClient                string

	userAgentSet               bool
	stainlessLangSet           bool
	stainlessRuntimeSet        bool
	stainlessRuntimeVersionSet bool
	stainlessOSSet             bool
	stainlessArchSet           bool
	stainlessRetryCountSet     bool
	stainlessTimeoutSet        bool
	stainlessReadTimeoutSet    bool
	trClientSet                bool

	userAgentTooLong       int
	stainlessValuesTooLong int
	trClientTooLong        int
}

func parseClientContext(raw clientContextHeaders) (*types.ClientContext, []string) {
	dropped := make([]string, 0, raw.stainlessValuesTooLong+2)
	for range raw.userAgentTooLong {
		dropped = append(dropped, "user_agent_too_long")
	}
	for range raw.stainlessValuesTooLong {
		dropped = append(dropped, "stainless_value_too_long")
	}
	for range raw.trClientTooLong {
		dropped = append(dropped, "x_tr_client_too_long")
	}

	cc := &types.ClientContext{}
	parsedAny := false

	if raw.userAgentSet || raw.userAgent != "" {
		if len(raw.userAgent) > maxClientUserAgentBytes {
			if raw.userAgentTooLong == 0 {
				dropped = append(dropped, "user_agent_too_long")
			}
		} else if raw.userAgent != "" {
			parseUserAgent(raw.userAgent, cc)
			parsedAny = true
		}
	}

	stainlessParsed := false
	lang, langOK := boundedStainlessValue(raw.stainlessLang, raw.stainlessLangSet)
	if !langOK {
		if len(raw.stainlessLang) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	} else if lang != "" {
		cc.Lang = normalizeStainlessLang(lang)
		stainlessParsed = true
	}

	runtimeName, runtimeOK := boundedStainlessValue(raw.stainlessRuntime, raw.stainlessRuntimeSet)
	if !runtimeOK {
		if len(raw.stainlessRuntime) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	}
	runtimeVersion, runtimeVersionOK := boundedStainlessValue(raw.stainlessRuntimeVersion, raw.stainlessRuntimeVersionSet)
	if !runtimeVersionOK {
		if len(raw.stainlessRuntimeVersion) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	}
	if runtimeOK && runtimeVersionOK {
		if normalized := normalizeStainlessRuntime(runtimeName, runtimeVersion); normalized != "" {
			cc.Runtime = normalized
			stainlessParsed = true
		}
	}

	osValue, osOK := boundedStainlessValue(raw.stainlessOS, raw.stainlessOSSet)
	if !osOK {
		if len(raw.stainlessOS) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	} else if osValue != "" {
		cc.OS = normalizeStainlessOS(osValue)
		stainlessParsed = true
	}

	arch, archOK := boundedStainlessValue(raw.stainlessArch, raw.stainlessArchSet)
	if !archOK {
		if len(raw.stainlessArch) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	} else if arch != "" {
		cc.Arch = normalizeStainlessArch(arch)
		stainlessParsed = true
	}

	retryCount, retryOK := boundedStainlessValue(raw.stainlessRetryCount, raw.stainlessRetryCountSet)
	if !retryOK {
		if len(raw.stainlessRetryCount) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	} else if raw.stainlessRetryCountSet || retryCount != "" {
		attempt, err := strconv.Atoi(retryCount)
		if err != nil || attempt < 0 || attempt > 99 {
			dropped = append(dropped, "stainless_retry_count")
		} else {
			cc.Attempt = intPointer(attempt)
			stainlessParsed = true
		}
	}

	timeout, timeoutOK := boundedStainlessValue(raw.stainlessTimeout, raw.stainlessTimeoutSet)
	if !timeoutOK {
		if len(raw.stainlessTimeout) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	}
	readTimeout, readTimeoutOK := boundedStainlessValue(raw.stainlessReadTimeout, raw.stainlessReadTimeoutSet)
	if !readTimeoutOK {
		if len(raw.stainlessReadTimeout) > maxClientStainlessValueBytes {
			dropped = append(dropped, "stainless_value_too_long")
		}
	}
	if timeoutOK && (raw.stainlessTimeoutSet || timeout != "") {
		if timeoutMS, ok := parseStainlessTimeout(timeout); ok {
			cc.TimeoutMS = timeoutMS
			stainlessParsed = true
		} else {
			dropped = append(dropped, "stainless_timeout")
			if readTimeoutOK && (raw.stainlessReadTimeoutSet || readTimeout != "") {
				if timeoutMS, ok := parseStainlessTimeout(readTimeout); ok {
					cc.TimeoutMS = timeoutMS
					stainlessParsed = true
				} else {
					dropped = append(dropped, "stainless_timeout")
				}
			}
		}
	} else if readTimeoutOK && (raw.stainlessReadTimeoutSet || readTimeout != "") {
		if timeoutMS, ok := parseStainlessTimeout(readTimeout); ok {
			cc.TimeoutMS = timeoutMS
			stainlessParsed = true
		} else {
			dropped = append(dropped, "stainless_timeout")
		}
	}
	parsedAny = parsedAny || stainlessParsed

	trParsed := false
	if raw.trClientSet || raw.trClient != "" {
		if len(raw.trClient) > maxTRClientHeaderBytes {
			if raw.trClientTooLong == 0 {
				dropped = append(dropped, "x_tr_client_too_long")
			}
		} else {
			trContext, ok := parseTRClientHeader(raw.trClient)
			if !ok {
				dropped = append(dropped, "x_tr_client_grammar")
			} else {
				applyTRClientContext(cc, trContext)
				trParsed = true
				parsedAny = true
			}
		}
	}

	if !parsedAny {
		return nil, dropped
	}
	cc.V = 1
	switch {
	case trParsed:
		cc.Source = "tr"
	case stainlessParsed:
		cc.Source = "stainless"
	default:
		cc.Source = "none"
	}
	if err := cc.Validate(); err != nil {
		fields := strings.Fields(err.Error())
		field := "unknown"
		if len(fields) > 0 {
			field = fields[len(fields)-1]
		}
		dropped = append(dropped, "validate:"+field)
		return nil, dropped
	}
	return cc, dropped
}

func parseUserAgent(userAgent string, cc *types.ClientContext) {
	if matches := trustedRouterUAPattern.FindStringSubmatch(userAgent); matches != nil && validClientSemver(matches[2]) {
		cc.SDK = "tr-" + matches[1]
		cc.SDKVersion = matches[2]
		if len(matches) >= 6 && matches[4] != "" {
			runtime := matches[4] + "/" + matches[5]
			if clientContextRuntimePattern.MatchString(runtime) {
				cc.Runtime = runtime
			}
		}
		return
	}
	if matches := vendorUAPattern.FindStringSubmatch(userAgent); matches != nil {
		vendor := strings.ToLower(matches[1])
		language := strings.ToLower(matches[2])
		switch language {
		case "python", "js", "go", "java":
			cc.SDK = vendor + "-" + language
		default:
			cc.SDK = vendor + "-other"
		}
		if len(matches) >= 4 && validClientSemver(matches[3]) {
			cc.SDKVersion = matches[3]
		}
		return
	}
	cc.SDK = "other"
}

func validClientSemver(value string) bool {
	return len(value) <= 32 && clientContextSemverPattern.MatchString(value)
}

func boundedStainlessValue(value string, set bool) (string, bool) {
	if !set && value == "" {
		return "", true
	}
	if len(value) > maxClientStainlessValueBytes {
		return "", false
	}
	return value, true
}

func normalizeStainlessLang(value string) string {
	switch strings.ToLower(value) {
	case "python", "js", "go", "java", "kotlin", "ruby", "csharp", "php", "swift", "dart":
		return strings.ToLower(value)
	default:
		return "other"
	}
}

func normalizeStainlessRuntime(name, version string) string {
	name = strings.ToLower(name)
	if base, _, found := strings.Cut(name, ":"); found {
		name = base
	}
	if len(version) > 1 && (version[0] == 'v' || version[0] == 'V') {
		version = version[1:]
	}
	runtime := name + "/" + version
	if !clientContextRuntimePattern.MatchString(runtime) {
		return ""
	}
	return runtime
}

func normalizeStainlessOS(value string) string {
	switch strings.ToLower(value) {
	case "macos":
		return "macos"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	case "ios":
		return "ios"
	case "android":
		return "android"
	case "freebsd":
		return "freebsd"
	default:
		return "other"
	}
}

func normalizeStainlessArch(value string) string {
	switch strings.ToLower(value) {
	case "x64", "x32", "arm", "arm64", "wasm":
		return strings.ToLower(value)
	default:
		return "other"
	}
}

func parseStainlessTimeout(value string) (int, bool) {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, false
	}
	milliseconds := seconds * 1000
	if milliseconds < 1 || milliseconds > 3_600_000 {
		return 0, false
	}
	return int(milliseconds), true
}

func parseTRClientHeader(value string) (*types.ClientContext, bool) {
	parts := strings.Split(value, ";")
	if len(parts) == 0 || parts[0] != "v=1" {
		return nil, false
	}
	parsed := &types.ClientContext{}
	seen := make(map[string]struct{}, len(parts)-1)
	for _, part := range parts[1:] {
		key, item, ok := strings.Cut(part, "=")
		if !ok || strings.Contains(item, "=") || !trClientValuePattern.MatchString(item) {
			return nil, false
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, false
		}
		seen[key] = struct{}{}
		switch key {
		case "a":
			attempt, ok := parseBoundedInt(item, 99)
			if !ok {
				return nil, false
			}
			parsed.Attempt = intPointer(attempt)
		case "po":
			if !clientValueAllowed(item, "none", "http_error", "transport_error", "timeout", "stream_broken") {
				return nil, false
			}
			parsed.PrevOutcome = item
		case "pc":
			if !clientValueAllowed(item,
				"none", "dns", "tls", "connect_refused", "connect_timeout", "connect_error", "read_timeout", "write_timeout",
				"pool_timeout", "protocol_error", "reset", "io_error", "proxy_error", "stream_stalled", "unknown",
			) {
				return nil, false
			}
			parsed.PrevErrorClass = item
		case "ph":
			if !clientValueAllowed(item, "none", "apex", "ally", "uptime", "us_central1", "us_east4", "europe_west4", "control", "custom") {
				return nil, false
			}
			parsed.PrevHost = item
		case "pm":
			milliseconds, ok := parseBoundedInt(item, 3_600_000)
			if !ok {
				return nil, false
			}
			parsed.PrevElapsedMS = intPointer(milliseconds)
		case "sm":
			milliseconds, ok := parseBoundedInt(item, 3_600_000)
			if !ok {
				return nil, false
			}
			parsed.SinceFirstMS = intPointer(milliseconds)
		case "s":
			stream, ok := parseHeaderBool(item)
			if !ok {
				return nil, false
			}
			parsed.Stream = boolPointer(stream)
		case "fo":
			failoverUsed, ok := parseHeaderBool(item)
			if !ok {
				return nil, false
			}
			parsed.FailoverUsed = boolPointer(failoverUsed)
		default:
			return nil, false
		}
	}
	return parsed, true
}

func applyTRClientContext(destination, source *types.ClientContext) {
	if source.Attempt != nil {
		destination.Attempt = source.Attempt
	}
	destination.PrevOutcome = source.PrevOutcome
	destination.PrevErrorClass = source.PrevErrorClass
	destination.PrevHost = source.PrevHost
	destination.PrevElapsedMS = source.PrevElapsedMS
	destination.SinceFirstMS = source.SinceFirstMS
	destination.Stream = source.Stream
	destination.FailoverUsed = source.FailoverUsed
}

func parseBoundedInt(value string, maximum int) (int, bool) {
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= 0 && parsed <= maximum
}

func parseHeaderBool(value string) (bool, bool) {
	switch value {
	case "0":
		return false, true
	case "1":
		return true, true
	default:
		return false, false
	}
}

func clientValueAllowed(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func intPointer(value int) *int    { return &value }
func boolPointer(value bool) *bool { return &value }
