package types

import (
	"regexp"
	"strings"
)

// polyphemusModelIDPattern matches a catalogue model id with an optional provider prefix.
var polyphemusModelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]*(/[a-zA-Z0-9][a-zA-Z0-9._+-]*)?$`)
var polyphemusZooPattern = regexp.MustCompile(`^[a-zA-Z0-9*][a-zA-Z0-9._+*-]*(/[a-zA-Z0-9*][a-zA-Z0-9._+*-]*)?$`)

const (
	MinPolyphemusXPerf       = 0.1
	MaxPolyphemusXPerf       = 1.0
	maxPolyphemusZooEntries  = 64
	maxPolyphemusZooBytes    = 2048
	maxPolyphemusXPerfIDSize = 128
)

// PolyphemusOptions are the former selector's routing controls. They are still
// validated and accepted so existing clients keep working, but the local
// classifier ignores them (docs/providers/polyphemus.md).
// XPerf was a quality bar: a float64 in [MinPolyphemusXPerf, MaxPolyphemusXPerf],
// or a model id. ModelZoo was comma-separated model patterns (`*` wildcards).
type PolyphemusOptions struct {
	XPerf    any    `json:"x_perf,omitempty"`
	ModelZoo string `json:"model_zoo,omitempty"`
}

// Validate returns the offending field name ("x_perf" or "model_zoo"), or "".
func (c PolyphemusOptions) Validate() string {
	switch v := c.XPerf.(type) {
	case float64:
		if !(v >= MinPolyphemusXPerf && v <= MaxPolyphemusXPerf) {
			return "x_perf"
		}
	case string:
		if len(v) > maxPolyphemusXPerfIDSize || !polyphemusModelIDPattern.MatchString(v) {
			return "x_perf"
		}
	default:
		return "x_perf"
	}
	if c.ModelZoo == "" {
		return ""
	}
	entries := strings.Split(c.ModelZoo, ",")
	if len(c.ModelZoo) > maxPolyphemusZooBytes || len(entries) > maxPolyphemusZooEntries {
		return "model_zoo"
	}
	for _, entry := range entries {
		if !polyphemusZooPattern.MatchString(strings.TrimSpace(entry)) {
			return "model_zoo"
		}
	}
	return ""
}
