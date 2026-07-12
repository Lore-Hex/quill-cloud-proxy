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
	encoded, err := json.Marshal(r.Trace)
	if err != nil {
		return &AttributionValidationError{Message: "trace must contain valid JSON values"}
	}
	if len(encoded) > MaxTraceUTF8Bytes {
		return &AttributionValidationError{Message: "trace must use at most 8192 UTF-8 bytes"}
	}
	items, err := traceItemCount(r.Trace, 1)
	if err != nil {
		return err
	}
	if items > MaxTraceItems {
		return &AttributionValidationError{Message: "trace may contain at most 256 keys and array elements"}
	}
	return nil
}

func boundedAttributionString(value, field string, limit int) error {
	if utf8.RuneCountInString(value) > limit {
		return &AttributionValidationError{Message: fmt.Sprintf("%s may contain at most %d characters", field, limit)}
	}
	return nil
}

func traceItemCount(value any, depth int) (int, error) {
	if depth > MaxTraceDepth {
		return 0, &AttributionValidationError{Message: "trace may be at most 8 levels deep"}
	}
	switch item := value.(type) {
	case map[string]any:
		count := len(item)
		for _, child := range item {
			childCount, err := traceItemCount(child, depth+1)
			if err != nil {
				return 0, err
			}
			count += childCount
		}
		return count, nil
	case []any:
		count := len(item)
		for _, child := range item {
			childCount, err := traceItemCount(child, depth+1)
			if err != nil {
				return 0, err
			}
			count += childCount
		}
		return count, nil
	default:
		return 0, nil
	}
}

func IsAttributionValidationError(err error) (*AttributionValidationError, bool) {
	if err == nil {
		return nil, false
	}
	attributionErr, ok := err.(*AttributionValidationError)
	return attributionErr, ok
}
