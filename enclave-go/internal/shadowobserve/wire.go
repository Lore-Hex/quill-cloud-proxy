package shadowobserve

import (
	"encoding/json"
)

const RefreshPath = "/internal/speculation/shadow/refresh"
const MaxIdentities = 256
const MaxBatch = 64
const MaxResponseBytes = 64 * 70000

// Identity contains only the resolved ordinary authorization binding.
type Identity struct {
	KeyID        string `json:"key_id"`
	LookupDigest string `json:"lookup_digest"`
	WorkspaceID  string `json:"workspace_id"`
}

// Byte validators have no package-init work and never scan unbounded input.
func validIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := range s {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '.' || b == ':' || b == '-') {
			return false
		}
	}
	return true
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range s {
		b := s[i]
		if !(b >= 'a' && b <= 'f' || b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}
func (i Identity) Valid() bool {
	return validIdentifier(i.KeyID) && validIdentifier(i.WorkspaceID) && validDigest(i.LookupDigest)
}

// ResolvedWorkspace validates optional authenticated denial metadata; a missing
// key or lookup is not invented or installed in the hot-set identity index.
func (i Identity) ResolvedWorkspace() bool {
	return validIdentifier(i.WorkspaceID) && (i.KeyID == "" || validIdentifier(i.KeyID)) && (i.LookupDigest == "" || validDigest(i.LookupDigest))
}

// Miss is deliberately open: unknown bounded codes remain misses, never ordinary errors.
type Miss struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
}

func NewMiss(status int, code string) *Miss {
	if !validIdentifier(code) {
		code = "malformed-response"
	}
	return &Miss{status, code}
}

type Result struct {
	Identity
	Grant string `json:"grant,omitempty"`
	Miss  *Miss  `json:"-"`
}

func EncodeBatch(items []Identity) ([]byte, *Miss) {
	if len(items) == 0 {
		return nil, NewMiss(400, "batch-invalid")
	}
	if len(items) > MaxBatch {
		return nil, NewMiss(413, "batch-too-large")
	}
	for _, i := range items {
		if !i.Valid() {
			return nil, NewMiss(400, "batch-invalid")
		}
	}
	b, err := json.Marshal(struct {
		Items []Identity `json:"items"`
	}{items})
	if err != nil || len(b) > 32768 {
		return nil, NewMiss(413, "batch-too-large")
	}
	return b, nil
}

func DecodeBatch(status int, body []byte, requested []Identity) ([]Result, *Miss) {
	if len(body) > MaxResponseBytes {
		return nil, NewMiss(status, "malformed-response")
	}
	var envelope struct {
		Authority string `json:"authority"`
		Miss      string `json:"miss"`
		Items     []struct {
			Identity
			Grant string `json:"grant"`
			Miss  string `json:"miss"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, NewMiss(status, "malformed-response")
	}
	if envelope.Miss != "" {
		return nil, NewMiss(status, envelope.Miss)
	}
	if status != 200 || envelope.Authority != "shadow-only" || len(envelope.Items) != len(requested) || len(envelope.Items) > MaxBatch {
		return nil, NewMiss(status, "malformed-response")
	}
	allowed := make(map[Identity]bool, len(requested))
	for _, i := range requested {
		allowed[i] = true
	}
	results := make([]Result, 0, len(envelope.Items))
	for _, i := range envelope.Items {
		if !allowed[i.Identity] || (i.Grant == "") == (i.Miss == "") || len(i.Grant) > 65536 {
			return nil, NewMiss(status, "malformed-response")
		}
		delete(allowed, i.Identity)
		r := Result{Identity: i.Identity, Grant: i.Grant}
		if i.Miss != "" {
			r.Miss = NewMiss(status, i.Miss)
		}
		results = append(results, r)
	}
	return results, nil
}
