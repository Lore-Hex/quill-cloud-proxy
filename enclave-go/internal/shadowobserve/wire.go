package shadowobserve

import (
	"encoding/json"
	"regexp"
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

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var lookupDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (i Identity) Valid() bool {
	return identifier.MatchString(i.KeyID) && identifier.MatchString(i.WorkspaceID) && lookupDigest.MatchString(i.LookupDigest)
}

// Miss is deliberately open: unknown bounded codes remain misses, never ordinary errors.
type Miss struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
}

func NewMiss(status int, code string) *Miss {
	if !identifier.MatchString(code) {
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
