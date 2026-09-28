package billingv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf16"
)

// CanonicalBytes returns compact ASCII JSON with lexical keys, explicit nulls,
// preserved array order and all defaults. Only validated contract models are accepted.
func CanonicalBytes(value any) ([]byte, error) {
	switch v := value.(type) {
	case Snapshot:
		if v.data == nil {
			return nil, failure("invalid_snapshot")
		}
		value = *v.data
	case Rates, Tier, Candidate, RawUsage, NormalizedUsage, Evaluation, Eligibility, TerminalEnvelope, AcceptanceOutcome:
		if err := validateGo(value, "invalid_type"); err != nil {
			return nil, err
		}
	default:
		return nil, failure("invalid_type")
	}
	return canonicalBytes(value)
}
func canonicalBytes(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	obj, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(obj); err != nil {
		return nil, err
	}
	raw = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	var ascii bytes.Buffer
	for _, r := range string(raw) {
		if r < 127 {
			ascii.WriteByte(byte(r))
		} else if r <= 0xffff {
			fmt.Fprintf(&ascii, `\u%04x`, r)
		} else {
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, `\u%04x\u%04x`, a, b)
		}
	}
	return ascii.Bytes(), nil
}
func CanonicalHash(value any) (string, error) {
	raw, err := CanonicalBytes(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Candidates returns a deep copy, including tier slices and optional bounds.
func (s Snapshot) Candidates() []Candidate {
	if s.data == nil {
		return nil
	}
	result := make([]Candidate, len(s.data.Candidates))
	copy(result, s.data.Candidates)
	for i := range result {
		result[i].Tiers = append([]Tier{}, result[i].Tiers...)
		for j := range result[i].Tiers {
			if p := result[i].Tiers[j].MaxPromptTokens; p != nil {
				v := *p
				result[i].Tiers[j].MaxPromptTokens = &v
			}
		}
	}
	return result
}
