package trustedrouter

import (
	"bytes"
	"encoding/json"
)

type shadowCaptureKey struct{}

// shadowCapture observes the original decoder's reads. It never buffers the
// response or an unknown value. Depth and string state suffice because the
// original decoder alone validates JSON. Limits include worst-case JSON escapes.
// Duplicate data objects merge, as they do in the legacy Authorization target.
type shadowCapture struct {
	done                                              bool
	depth                                             int
	inString, escaped, keyString, wantKey, dataObject bool
	key                                               [160]byte
	keyLen                                            int
	field                                             string
	policy, exclusion                                 json.RawMessage
	policySeen, policyOverflow, exclusionOverflow     bool
	binding                                           bool
}

func (s *shadowCapture) Write(p []byte) (int, error) {
	for _, b := range p {
		s.byte(b)
	}
	return len(p), nil
}

func (s *shadowCapture) byte(b byte) {
	if s.done {
		return
	}
	// Decode accepts a top-level null and may read ahead into another JSON
	// value. Such bytes belong to no Authorization in this response.
	if s.depth == 0 && b != '{' && b != '[' {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			s.done = true
		}
		return
	}
	// A value ends only at its containing object's separator, outside strings.
	if !s.inString && s.depth == 2 && s.dataObject && (b == ',' || b == '}') {
		s.endValue()
	}
	if s.field == "billing_shadow_policy" {
		captureShadowByte(&s.policy, &s.policyOverflow, b, 6*len(shadowPolicyV2)+2)
	} else if s.field == "billing_shadow_exclusion" {
		captureShadowByte(&s.exclusion, &s.exclusionOverflow, b, 6*shadowCertificateBytes+2)
	}

	if s.inString {
		if s.keyString && s.keyLen < len(s.key) {
			s.key[s.keyLen] = b
			s.keyLen++
		}
		if s.escaped {
			s.escaped = false
			return
		}
		if b == '\\' {
			s.escaped = true
			return
		}
		if b == '"' {
			s.inString = false
			s.keyString = false
		}
		return
	}
	switch b {
	case '"':
		s.inString = true
		s.keyString = s.wantKey && (s.depth == 1 || (s.depth == 2 && s.dataObject))
		if s.keyString {
			s.keyLen = 1
			s.key[0] = b
			s.wantKey = false
		}
	case ':':
		if s.depth == 1 || (s.depth == 2 && s.dataObject) {
			key := s.key[:s.keyLen]
			s.keyLen = 0
			if bytes.ContainsRune(key, '\\') {
				var decoded string
				if json.Unmarshal(key, &decoded) == nil {
					key = []byte(`"` + decoded + `"`)
				}
			}
			if s.depth == 1 {
				s.dataObject = bytes.EqualFold(key, []byte(`"data"`))
			} else {
				for _, name := range []string{"billing_shadow_policy", "billing_shadow_exclusion", "billing_shadow_binding"} {
					if len(key) == len(name)+2 && bytes.EqualFold(key[1:len(key)-1], []byte(name)) {
						s.field = name
						switch name {
						case "billing_shadow_policy":
							s.policySeen = true
							s.policy = s.policy[:0]
							s.policyOverflow = false
						case "billing_shadow_exclusion":
							s.exclusion = s.exclusion[:0]
							s.exclusionOverflow = false
						case "billing_shadow_binding":
							s.binding = true
						}
						break
					}
				}
			}
		}
	case '{', '[':
		if s.depth == 1 && b != '{' {
			s.dataObject = false
		}
		s.depth++
		s.wantKey = b == '{'
	case '}', ']':
		s.depth--
		if s.depth == 0 {
			s.done = true
		}
		if s.depth < 2 {
			s.dataObject = false
		}
	case ',':
		s.wantKey = true
	}
}

// Reuse bounded storage across duplicate keys. In particular an absent policy
// never causes per-value string decoding or allocation proportional to the
// number/size of ignored exclusion fields.
func captureShadowByte(raw *json.RawMessage, overflow *bool, b byte, limit int) {
	if *overflow {
		return
	}
	if len(*raw) == limit {
		*raw = (*raw)[:0]
		*overflow = true
		return
	}
	if *raw == nil {
		*raw = make([]byte, 0, limit)
	}
	*raw = append(*raw, b)
}

func (s *shadowCapture) endValue() { s.field = "" }

// The only metadata value capture boundary: reject before unbounded string
// decoding, then enforce the decoded limit. Rejected/present is a tiny null.
func boundedShadowString(raw []byte, overflow bool, limit int) json.RawMessage {
	var value string
	if overflow || len(raw) > 6*limit+2 || json.Unmarshal(raw, &value) != nil || len(value) > limit {
		return json.RawMessage(`null`)
	}
	// Preserve raw spelling for the existing tolerant policy reader. Certificate
	// decoding subsequently retains the original opaque string, never re-encodes it.
	return bytes.TrimSpace(raw)
}

func (s *shadowCapture) finish(a *Authorization) {
	// No policy means main's v1 path, including no new retained metadata.
	if !s.policySeen {
		return
	}
	a.BillingShadowPolicy = boundedShadowString(s.policy, s.policyOverflow, len(shadowPolicyV2))
	if s.exclusion != nil || s.exclusionOverflow {
		a.BillingShadowExclusion = boundedShadowString(s.exclusion, s.exclusionOverflow, shadowCertificateBytes)
	}
	a.shadowBindingPresent = s.binding
}
