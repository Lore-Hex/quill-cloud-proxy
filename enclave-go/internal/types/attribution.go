package types

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"unicode/utf8"
)

const (
	MaxAttributionUserRunes     = 256
	MaxAttributionSessionRunes  = 256
	MaxAttributionAppRunes      = 120
	MaxAttributionRefererRunes  = 2048
	MaxAttributionCategories    = 2
	MaxAttributionCategoryRunes = 30
	MaxTraceUTF8Bytes           = 8192
	MaxTraceDepth               = 8
	MaxTraceItems               = 256
)

var attributionCategoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type AttributionValidationError struct {
	Message string
}

func (e *AttributionValidationError) Error() string { return e.Message }

// ValidateAttribution checks metadata before authorization and may fill the
// app title from the referer host. It never reads prompt or output content.
func (r *OpenAIChatRequest) ValidateAttribution() error {
	if r == nil {
		return nil
	}
	if err := boundedAttributionString(r.User, "user", MaxAttributionUserRunes); err != nil {
		return err
	}
	if err := boundedAttributionString(r.SessionID, "session_id", MaxAttributionSessionRunes); err != nil {
		return err
	}
	if err := boundedAttributionString(r.App, "app title", MaxAttributionAppRunes); err != nil {
		return err
	}
	if err := boundedAttributionString(r.HTTPReferer, "HTTP-Referer", MaxAttributionRefererRunes); err != nil {
		return err
	}
	if r.HTTPReferer != "" {
		parsed, err := url.ParseRequestURI(r.HTTPReferer)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return &AttributionValidationError{Message: "HTTP-Referer must be an http or https URL"}
		}
		if r.App == "" {
			r.App = parsed.Hostname()
		}
	}
	if len(r.AppCategories) > MaxAttributionCategories {
		return &AttributionValidationError{Message: "app categories may contain at most 2 values"}
	}
	for _, category := range r.AppCategories {
		if utf8.RuneCountInString(category) > MaxAttributionCategoryRunes || !attributionCategoryPattern.MatchString(category) {
			return &AttributionValidationError{Message: "app categories must be lowercase kebab-case with at most 30 characters"}
		}
	}
	if r.Trace == nil {
		return nil
	}
	stats, err := traceItemStats(r.Trace, 1, traceStats{})
	if err != nil {
		return err
	}
	if stats.Items > MaxTraceItems {
		return &AttributionValidationError{Message: "trace may contain at most 256 keys and array elements"}
	}
	encoded, err := json.Marshal(r.Trace)
	if err != nil {
		return &AttributionValidationError{Message: "trace must contain valid JSON values"}
	}
	if len(encoded) > MaxTraceUTF8Bytes {
		return &AttributionValidationError{Message: "trace must use at most 8192 UTF-8 bytes"}
	}
	return nil
}

func boundedAttributionString(value, field string, limit int) error {
	if utf8.RuneCountInString(value) > limit {
		return &AttributionValidationError{Message: fmt.Sprintf("%s may contain at most %d characters", field, limit)}
	}
	return nil
}

type traceStats struct {
	Items    int
	MinBytes int
}

func traceItemStats(value any, depth int, stats traceStats) (traceStats, error) {
	if depth > MaxTraceDepth {
		return stats, &AttributionValidationError{Message: "trace may be at most 8 levels deep"}
	}
	stats.MinBytes += traceMinBytes(value)
	if stats.MinBytes > MaxTraceUTF8Bytes {
		return stats, &AttributionValidationError{Message: "trace must use at most 8192 UTF-8 bytes"}
	}
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			stats.Items++
			if stats.Items > MaxTraceItems {
				return stats, &AttributionValidationError{Message: "trace may contain at most 256 keys and array elements"}
			}
			stats.MinBytes += len(key)
			if stats.MinBytes > MaxTraceUTF8Bytes {
				return stats, &AttributionValidationError{Message: "trace must use at most 8192 UTF-8 bytes"}
			}
			nextStats, err := traceItemStats(child, depth+1, stats)
			if err != nil {
				return nextStats, err
			}
			stats = nextStats
		}
		return stats, nil
	case []any:
		for _, child := range item {
			stats.Items++
			if stats.Items > MaxTraceItems {
				return stats, &AttributionValidationError{Message: "trace may contain at most 256 keys and array elements"}
			}
			nextStats, err := traceItemStats(child, depth+1, stats)
			if err != nil {
				return nextStats, err
			}
			stats = nextStats
		}
		return stats, nil
	default:
		return stats, nil
	}
}

func traceMinBytes(value any) int {
	switch item := value.(type) {
	case map[string]any, []any:
		return 2
	case string:
		return len(item)
	case bool, nil:
		return 4
	default:
		return 1
	}
}

func IsAttributionValidationError(err error) (*AttributionValidationError, bool) {
	if err == nil {
		return nil, false
	}
	attributionErr, ok := err.(*AttributionValidationError)
	return attributionErr, ok
}
