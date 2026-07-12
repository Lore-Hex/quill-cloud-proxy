package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTagMapAcceptsPortableAWSStyleTags(t *testing.T) {
	var tags TagMap
	if err := json.Unmarshal([]byte(`{"environment":"production","team/name":"Legal Ops","empty":""}`), &tags); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if tags["environment"] != "production" || tags["team/name"] != "Legal Ops" {
		t.Fatalf("tags = %#v", tags)
	}
}

func TestTagMapRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "array", raw: `[{"Key":"team","Value":"legal"}]`, want: "object"},
		{name: "non-string", raw: `{"priority":7}`, want: "string values"},
		{name: "reserved aws", raw: `{"AWS:owner":"legal"}`, want: "reserved prefix"},
		{name: "reserved trustedrouter", raw: `{"trustedrouter:owner":"legal"}`, want: "reserved prefix"},
		{name: "punctuation", raw: `{"bad#key":"legal"}`, want: "unsupported characters"},
		{name: "line separator", raw: "{\"team\":\"legal\\u2028platform\"}", want: "unsupported characters"},
		{name: "paragraph separator", raw: "{\"team\":\"legal\\u2029platform\"}", want: "unsupported characters"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var tags TagMap
			err := json.Unmarshal([]byte(test.raw), &tags)
			var tagErr *TagValidationError
			if !errors.As(err, &tagErr) || !strings.Contains(tagErr.Error(), test.want) {
				t.Fatalf("err = %v, want TagValidationError containing %q", err, test.want)
			}
		})
	}
}

func TestRequestTagsCaptureInvalidCompatibleJSONWithoutFailingBodyDecode(t *testing.T) {
	for _, raw := range []string{
		`[{"Key":"team","Value":"legal"}]`,
		`{"priority":7}`,
		`{"bad#key":"legal"}`,
	} {
		var tags RequestTags
		if err := json.Unmarshal([]byte(raw), &tags); err != nil {
			t.Fatalf("Unmarshal(%s): %v", raw, err)
		}
		if tags.ValidationError() == nil {
			t.Fatalf("ValidationError(%s) = nil", raw)
		}
		if tags.Values() != nil {
			t.Fatalf("Values(%s) = %#v, want nil", raw, tags.Values())
		}
		encoded, err := json.Marshal(tags)
		if err != nil || string(encoded) != "null" {
			t.Fatalf("Marshal(%s) = %s, %v; want null", raw, encoded, err)
		}
	}
}

func TestTagMapEnforcesCountAndAggregateSize(t *testing.T) {
	tooMany := make(map[string]string, MaxTags+1)
	for index := range MaxTags + 1 {
		tooMany[fmt.Sprintf("key-%d", index)] = "value"
	}
	if _, err := ValidateTags(tooMany); err == nil || !strings.Contains(err.Error(), "at most 50") {
		t.Fatalf("count err = %v", err)
	}

	tooLarge := make(map[string]string, MaxTags)
	for index := range MaxTags {
		tooLarge[fmt.Sprintf("key-%02d", index)] = strings.Repeat("x", 90)
	}
	if _, err := ValidateTags(tooLarge); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Fatalf("size err = %v", err)
	}
}

func TestCloneTagsDetachesMap(t *testing.T) {
	original := TagMap{"team": "legal"}
	cloned := CloneTags(original)
	cloned["team"] = "platform"
	if original["team"] != "legal" {
		t.Fatalf("original mutated: %#v", original)
	}
}
