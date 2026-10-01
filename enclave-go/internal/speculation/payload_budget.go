package speculation

import (
	"math"
	"strconv"
	"unicode/utf8"
)

// encodedBudget counts encoding/json's escaped UTF-8 representation without
// allocating or invoking caller code. The input is the parsed JSON domain, not
// arbitrary marshalers. Container counts, raw string lengths and depth cap work
// before traversal; every visited node spends budget, including empty containers.
type encodedBudget struct{ remaining int }

func (b *encodedBudget) spend(n int) Reason {
	if n > b.remaining {
		return ReasonInputBound
	}
	b.remaining -= n
	return ReasonEligible
}

func (b *encodedBudget) text(s string) Reason {
	// Every UTF-8 input byte needs at least one output byte. Huge strings reject
	// here in constant time, without even validating/scanning their contents.
	if len(s) > b.remaining || b.remaining-len(s) < 2 {
		return ReasonInputBound
	}
	b.remaining -= 2
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && n == 1 {
			return ReasonPayload
		}
		size := n
		switch {
		case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t' || r == '\b' || r == '\f':
			size = 2
		case r < 0x20 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
			size = 6
		}
		if reason := b.spend(size); reason != ReasonEligible {
			return reason
		}
		s = s[n:]
	}
	return ReasonEligible
}

func (b *encodedBudget) value(v any, depth int) Reason {
	if depth > 64 {
		return ReasonInputBound
	}
	var digits [32]byte
	switch v := v.(type) {
	case string:
		return b.text(v)
	case nil:
		return b.spend(4)
	case bool:
		if v {
			return b.spend(4)
		}
		return b.spend(5)
	case int:
		return b.spend(len(strconv.AppendInt(digits[:0], int64(v), 10)))
	case int64:
		return b.spend(len(strconv.AppendInt(digits[:0], v, 10)))
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return ReasonPayload
		}
		// A conservative fixed bound avoids float formatting allocations.
		return b.spend(24)
	case []any:
		if len(v) > b.remaining/2 {
			return ReasonInputBound
		}
		if r := b.spend(2 + max(0, len(v)-1)); r != ReasonEligible {
			return r
		}
		for _, item := range v {
			if r := b.value(item, depth+1); r != ReasonEligible {
				return r
			}
		}
	case map[string]any:
		if len(v) > b.remaining/4 {
			return ReasonInputBound
		}
		if r := b.spend(2 + max(0, len(v)-1) + len(v)); r != ReasonEligible {
			return r
		}
		for k, item := range v {
			if r := b.text(k); r != ReasonEligible {
				return r
			}
			if r := b.value(item, depth+1); r != ReasonEligible {
				return r
			}
		}
	default:
		return ReasonPayload
	}
	return ReasonEligible
}

func precheckChat(body map[string]any, prefix []string, cacheScope string, limit int) Reason {
	b := encodedBudget{limit}
	if cacheScope != "" {
		if r := b.spend(21); r != ReasonEligible {
			return r
		}
		if r := b.text(cacheScope); r != ReasonEligible {
			return r
		}
	}
	if len(prefix) > limit/30 {
		return ReasonInputBound
	}
	for _, text := range prefix {
		// Serialized system message keys, role and separators, excluding content.
		if r := b.spend(29); r != ReasonEligible {
			return r
		}
		if r := b.text(text); r != ReasonEligible {
			return r
		}
	}
	return b.value(body, 0)
}
