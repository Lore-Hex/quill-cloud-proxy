package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxTags          = 50
	MaxTagKeyRunes   = 128
	MaxTagValueRunes = 256
	MaxTagsUTF8Bytes = 4096
)

// TagValidationError is safe to expose as an invalid_tags client error.
type TagValidationError struct {
	Message string
}

func (e *TagValidationError) Error() string { return e.Message }

// TagMap implements the portable subset of AWS resource-tag semantics used
// by TrustedRouter request attribution.
type TagMap map[string]string

func (tags *TagMap) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*tags = nil
		return nil
	}
	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		return &TagValidationError{Message: "tags must be an object with string values"}
	}
	validated, err := ValidateTags(decoded)
	if err != nil {
		return err
	}
	*tags = validated
	return nil
}

func ValidateTags(tags map[string]string) (TagMap, error) {
	if len(tags) > MaxTags {
		return nil, &TagValidationError{Message: fmt.Sprintf("tags may contain at most %d entries", MaxTags)}
	}
	validated := make(TagMap, len(tags))
	for key, value := range tags {
		keyRunes := utf8.RuneCountInString(key)
		if keyRunes < 1 || keyRunes > MaxTagKeyRunes {
			return nil, &TagValidationError{Message: "tag key must contain 1 to 128 characters"}
		}
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "aws:") || strings.HasPrefix(lowerKey, "trustedrouter:") {
			return nil, &TagValidationError{Message: "tag key uses a reserved prefix"}
		}
		if !portableTagText(key) {
			return nil, &TagValidationError{Message: "tag key contains unsupported characters"}
		}
		if utf8.RuneCountInString(value) > MaxTagValueRunes {
			return nil, &TagValidationError{Message: "tag value must contain at most 256 characters"}
		}
		if !portableTagText(value) {
			return nil, &TagValidationError{Message: "tag value contains unsupported characters"}
		}
		validated[key] = value
	}
	encoded, err := json.Marshal(validated)
	if err != nil {
		return nil, &TagValidationError{Message: "tags could not be encoded"}
	}
	if len(encoded) > MaxTagsUTF8Bytes {
		return nil, &TagValidationError{Message: "tags must use at most 4096 UTF-8 bytes"}
	}
	return validated, nil
}

func CloneTags(tags TagMap) TagMap {
	if tags == nil {
		return nil
	}
	cloned := make(TagMap, len(tags))
	for key, value := range tags {
		cloned[key] = value
	}
	return cloned
}

func portableTagText(value string) bool {
	for _, char := range value {
		if strings.ContainsRune("+-=._:/@", char) {
			continue
		}
		if unicode.IsLetter(char) || unicode.IsNumber(char) || unicode.Is(unicode.Z, char) {
			continue
		}
		return false
	}
	return true
}
