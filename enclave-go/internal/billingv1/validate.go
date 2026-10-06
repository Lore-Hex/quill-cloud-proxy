package billingv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Error is a stable failure class with optional field detail. Code matches the
// frozen fixture's invalid_* classes or exact semantic/exclusion reason. Kind
// distinguishes string_type errors without discarding the enclosing class.
type Error struct{ Code, Field, Kind string }

func (e *Error) Error() string  { return e.Code + ": " + e.Field + " " + e.Kind }
func failure(code string) error { return &Error{Code: code} }

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9_./:@+\-]+$`)
var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// decodeJSON preserves numeric spelling and rejects duplicate keys at every
// depth, trailing documents, non-UTF-8 encodings, and excessive nesting.
func decodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, failure("invalid_encoding")
	}
	if err := validateStringEscapes(raw); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON: %v", err)
	}
	return v, nil
}

// Scan the original JSON before decoding strings:
// encoding/json replaces lone surrogate escapes with U+FFFD. Escaped backslashes
// are skipped, and a high surrogate must immediately precede a low surrogate.
// Scanning the whole document includes keys and unknown fields at every depth.
func validateStringEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		u, ok := unicodeEscape(raw[i:])
		if !ok {
			i++
			continue
		}
		i += 5
		if u >= 0xd800 && u <= 0xdbff {
			low, paired := unicodeEscape(raw[i+1:])
			if !paired || low < 0xdc00 || low > 0xdfff {
				return failure("invalid_string")
			}
			i += 6
		} else if u >= 0xdc00 && u <= 0xdfff {
			return failure("invalid_string")
		}
	}
	return nil
}

func unicodeEscape(raw []byte) (uint64, bool) {
	if len(raw) < 6 || raw[0] != '\\' || raw[1] != 'u' {
		return 0, false
	}
	u, err := strconv.ParseUint(string(raw[2:6]), 16, 16)
	return u, err == nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		result := map[string]any{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key")
			}
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key")
			}
			value, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			result[key] = value
		}
		if _, err = d.Token(); err != nil {
			return nil, err
		}
		return result, nil
	case '[':
		result := []any{}
		for d.More() {
			value, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			result = append(result, value)
		}
		if _, err = d.Token(); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter")
	}
}

func parseModel(raw []byte, target any, code string) error {
	value, err := decodeJSON(raw)
	if err != nil {
		if wireError, ok := err.(*Error); ok {
			return wireError
		}
		return &Error{Code: code, Kind: err.Error()}
	}
	err = validateValue(value, reflect.ValueOf(target).Elem(), reflect.StructTag(""), "")
	if err != nil {
		e := err.(*Error)
		return &Error{Code: code, Field: e.Field, Kind: e.Kind}
	}
	return nil
}
func invalid(path, kind string) error { return &Error{Code: "invalid_type", Field: path, Kind: kind} }
func validateValue(input any, dst reflect.Value, tag reflect.StructTag, path string) error {
	if dst.Kind() == reflect.Pointer {
		if input == nil {
			dst.SetZero()
			return nil
		}
		dst.Set(reflect.New(dst.Type().Elem()))
		return validateValue(input, dst.Elem(), tag, path)
	}
	if tag.Get("check") == "null" {
		if input != nil {
			return invalid(path, "null required")
		}
		return nil
	}
	switch dst.Kind() {
	case reflect.Int64:
		n, ok := input.(json.Number)
		if !ok {
			return invalid(path, "strict integer required")
		}
		value, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil || value < 0 {
			return invalid(path, "integer outside int64 domain")
		}
		if lit := tag.Get("literal"); lit != "" && string(n) != lit {
			return invalid(path, "unknown literal")
		}
		dst.SetInt(value)
	case reflect.String:
		s, ok := input.(string)
		if !ok {
			return invalid(path, "string_type")
		}
		if lit := tag.Get("literal"); lit != "" {
			found := false
			for _, x := range strings.Split(lit, "|") {
				if s == x {
					found = true
				}
			}
			if !found {
				return invalid(path, "unknown literal")
			}
		}
		switch tag.Get("check") {
		case "identity":
			if len(s) > 512 || !identityPattern.MatchString(s) {
				return invalid(path, "invalid identity")
			}
		case "nonce":
			if len(s) > 64 || !noncePattern.MatchString(s) {
				return invalid(path, "invalid nonce")
			}
		case "digest":
			if !digestPattern.MatchString(s) {
				return invalid(path, "invalid digest")
			}
		}
		dst.SetString(s)
	case reflect.Bool:
		b, ok := input.(bool)
		if !ok {
			return invalid(path, "strict boolean required")
		}
		dst.SetBool(b)
	case reflect.Slice:
		values, ok := input.([]any)
		if !ok {
			return invalid(path, "array required")
		}
		minimum := 0
		if tag.Get("bounds") == "1,64" {
			minimum = 1
		}
		if len(values) < minimum || len(values) > 64 {
			return invalid(path, "collection bounds")
		}
		dst.Set(reflect.MakeSlice(dst.Type(), len(values), len(values)))
		for i, value := range values {
			if err := validateValue(value, dst.Index(i), "", fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		obj, ok := input.(map[string]any)
		if !ok {
			return invalid(path, "object required")
		}
		typ := dst.Type()
		known := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := field.Tag.Get("json")
			known[name] = true
			value, exists := obj[name]
			if !exists {
				def, has := field.Tag.Lookup("default")
				if !has {
					return invalid(joinPath(path, name), "required")
				}
				var err error
				value, err = decodeJSON([]byte(def))
				if err != nil {
					return err
				}
			}
			if err := validateValue(value, dst.Field(i), field.Tag, joinPath(path, name)); err != nil {
				return err
			}
		}
		for name := range obj {
			if !known[name] {
				return invalid(joinPath(path, name), "unknown field")
			}
		}
		if err := validateSemantics(dst.Interface()); err != nil {
			return invalid(path, err.Error())
		}
	default:
		return invalid(path, "unsupported type")
	}
	return nil
}
func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
func validateSemantics(v any) error {
	switch x := v.(type) {
	case Candidate:
		if x.RequestFeeMicro != 0 {
			return failure("request_fee")
		}
		convention := "includes_cache"
		if x.Provider == "anthropic" {
			convention = "excludes_cache"
		}
		if x.PromptConvention != convention || !strings.HasPrefix(x.ModelID, x.Provider+"/") {
			return failure("unsupported_adapter")
		}
		previous := int64(-1)
		for i, t := range x.Tiers {
			if t.MaxPromptTokens == nil {
				if i != len(x.Tiers)-1 {
					return failure("unbounded tier must be last")
				}
			} else {
				if *t.MaxPromptTokens <= previous {
					return failure("tier boundaries must increase")
				}
				previous = *t.MaxPromptTokens
			}
		}
	case snapshotData:
		for i := 1; i < len(x.Candidates); i++ {
			if x.Candidates[i-1].EndpointID >= x.Candidates[i].EndpointID {
				return failure("candidates must be unique and sorted")
			}
		}
	case NormalizedUsage:
		sum, err := checkedAdd(x.UncachedInputTokens, x.CacheReadTokens)
		if err != nil {
			return err
		}
		sum, err = checkedAdd(sum, x.CacheCreationTokens)
		if err != nil {
			return err
		}
		if sum != x.TotalPromptTokens || x.ReasoningTokens > x.OutputTokens {
			return failure("malformed_usage")
		}
	case TerminalEnvelope:
		if x.TerminalKind == "refund" && x.ChargeMicro != 0 {
			return failure("refund must be zero")
		}
	case AcceptanceOutcome:
		durable := x.Status == "accepted" || x.Status == "duplicate"
		if durable {
			if x.PayloadHash == nil || x.SettlementStatus == nil || *x.SettlementStatus != "pending" {
				return failure("durable outcome requires hash and pending status")
			}
		} else if x.PayloadHash != nil || x.SettlementStatus != nil {
			return failure("rejection cannot acknowledge durability")
		}
	}
	return nil
}

func ParseSnapshot(raw []byte) (Snapshot, error) {
	var data snapshotData
	err := parseModel(raw, &data, "invalid_snapshot")
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{data: &data}, nil
}
func ParseRawUsage(raw []byte) (RawUsage, error) {
	var v RawUsage
	err := parseModel(raw, &v, "invalid_usage")
	return v, err
}
func ParseEligibility(raw []byte) (Eligibility, error) {
	var v Eligibility
	err := parseModel(raw, &v, "invalid_context")
	return v, err
}
func ParseEnvelope(raw []byte) (TerminalEnvelope, error) {
	var v TerminalEnvelope
	err := parseModel(raw, &v, "invalid_envelope")
	return v, err
}
func ParseAcceptance(raw []byte) (AcceptanceOutcome, error) {
	var v AcceptanceOutcome
	err := parseModel(raw, &v, "invalid_acceptance")
	return v, err
}
func DefaultEligibility() Eligibility {
	return Eligibility{Typed: true, UsageType: "Credits", Authority: "local", RouteType: "chat.completions"}
}

// validateGo applies the same checks to values constructed directly in Go.
func validateGo(v any, code string) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return failure(code)
	}
	target := reflect.New(reflect.TypeOf(v)).Interface()
	return parseModel(raw, target, code)
}
