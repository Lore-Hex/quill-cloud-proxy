package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// lenientRequestHeader opts one request into lenient parsing. An API key can
// opt every request in through its lenient setting on the control plane.
const lenientRequestHeader = "x-trustedrouter-lenient"

// ignoredParametersHeader lists, on the response, every parameter a lenient
// request dropped. A dropped field is never silent: the client can see it.
const ignoredParametersHeader = "x-trustedrouter-ignored-parameters"

const (
	keyLenienceTTL        = time.Minute
	keyLenienceMaxEntries = 4096
	keyLenienceTimeout    = 2 * time.Second
)

func lenientHeaderEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

type keyLenienceEntry struct {
	lenient bool
	expires time.Time
}

// keyLenienceCache remembers each key's lenient setting briefly so a key that
// relies on lenient mode costs one validation call a minute, not one a request.
// Only requests that would otherwise be refused ever consult it.
type keyLenienceCache struct {
	mu      sync.Mutex
	entries map[string]keyLenienceEntry
}

var keyLenience = &keyLenienceCache{entries: map[string]keyLenienceEntry{}}

func (c *keyLenienceCache) get(lookupHash string, now time.Time) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[lookupHash]
	if !ok || now.After(entry.expires) {
		return false, false
	}
	return entry.lenient, true
}

func (c *keyLenienceCache) put(lookupHash string, lenient bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= keyLenienceMaxEntries {
		for hash, entry := range c.entries {
			if now.After(entry.expires) {
				delete(c.entries, hash)
			}
		}
		if len(c.entries) >= keyLenienceMaxEntries {
			c.entries = map[string]keyLenienceEntry{}
		}
	}
	c.entries[lookupHash] = keyLenienceEntry{lenient: lenient, expires: now.Add(keyLenienceTTL)}
}

// lookupKeyLenience verifies the bearer with the control plane and returns
// whether its key is lenient. valid is false for any failure, so the request
// keeps the strict contract. A key's answer is cached for a minute.
//
// The lookup carries rejection, the refusal a strict parse would return, when
// one is given: a strict key records it there, as the failure path's own
// validation would, and the verified identity comes back so that validation
// is not repeated. It is marked a lenience probe, so a lenient key's control
// plane does not count it: that request goes on.
func lookupKeyLenience(
	ctx context.Context,
	gateway *trustedrouter.Client,
	bearer string,
	route string,
	rejection *adapter.AdapterError,
	body []byte,
) (valid bool, lenient bool, verified *trustedrouter.KeyIdentity) {
	if bearer == "" || gateway == nil || !gateway.Enabled() {
		return false, false, nil
	}
	lookupHash := trustedrouter.LookupHash(bearer)
	now := time.Now()
	if lenient, ok := keyLenience.get(lookupHash, now); ok {
		return true, lenient, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, keyLenienceTimeout)
	defer cancel()
	lookupCtx = trustedrouter.WithLenienceProbe(lookupCtx)
	if rejection != nil {
		preview, truncated := trustedrouter.ContractParameterValue(body, rejection.Context)
		lookupCtx = trustedrouter.WithContractRejection(lookupCtx, rejection.Status, rejection.Context, preview, truncated)
	}
	identity, err := gateway.ValidateKeyInfo(lookupCtx, bearer, route)
	if err != nil || identity == nil || identity.WorkspaceID == "" {
		return false, false, nil
	}
	keyLenience.put(lookupHash, identity.Lenient, now)
	return true, identity.Lenient, identity
}

// headerLenienceAllowed admits a request-level opt-in only for a verified
// key, so an unauthenticated caller cannot make the gateway re-parse a body.
// Without a control plane the registry already authenticated the bearer.
func headerLenienceAllowed(ctx context.Context, gateway *trustedrouter.Client, bearer, route string, body []byte) bool {
	if gateway == nil || !gateway.Enabled() {
		return true
	}
	valid, _, _ := lookupKeyLenience(ctx, gateway, bearer, route, nil, body)
	return valid
}

// parseWithLenience parses strictly first. Only when the strict parse fails on
// a parameter lenient mode may drop does it look up whether the request or key
// opted in, so requests that already pass pay nothing. It returns the body
// that parsed; later stages that re-read the body must use it.
//
// later, when set, runs checks a later stage (the translation) applies to a
// parsed request. A droppable failure there is handled here for a lenient
// request, before any credit is held; for a strict request it is left to that
// stage, which reports it as it always has.
func parseWithLenience[T any](
	ctx context.Context,
	log io.Writer,
	statsConn *responseStatsConn,
	gateway *trustedrouter.Client,
	bearer string,
	route string,
	requestLogID string,
	headerLenient bool,
	identity *requestAuditIdentity,
	body []byte,
	parse func([]byte) (T, error),
	later func(T, []byte) error,
) (T, []byte, error) {
	withLater := func(candidate []byte) (T, error) {
		parsed, err := parse(candidate)
		if err == nil && later != nil {
			if laterErr := later(parsed, candidate); laterErr != nil {
				if _, droppable := adapter.LenientDropPath(laterErr); droppable {
					return parsed, laterErr
				}
			}
		}
		return parsed, err
	}
	result, err := parse(body)
	if err == nil {
		if later == nil {
			return result, body, nil
		}
		laterErr := later(result, body)
		if laterErr == nil {
			return result, body, nil
		}
		if _, droppable := adapter.LenientDropPath(laterErr); !droppable {
			return result, body, nil
		}
		if headerLenient {
			if !headerLenienceAllowed(ctx, gateway, bearer, route, body) {
				return result, body, nil
			}
		} else if _, lenient, _ := lookupKeyLenience(ctx, gateway, bearer, route, nil, body); !lenient {
			// No refusal is attached: a strict key gets the later stage's
			// answer, exactly as before.
			return result, body, nil
		}
		return finishLenientParse(log, statsConn, route, requestLogID, body, withLater)
	}
	if _, droppable := adapter.LenientDropPath(err); !droppable {
		return result, body, err
	}
	if headerLenient {
		if !headerLenienceAllowed(ctx, gateway, bearer, route, body) {
			return result, body, err
		}
	} else {
		var rejection *adapter.AdapterError
		_ = asAdapterErr(err, &rejection)
		_, lenient, verified := lookupKeyLenience(ctx, gateway, bearer, route, rejection, body)
		if !lenient {
			if verified != nil && identity != nil && verified.WorkspaceID != "" {
				identity.workspaceID = verified.WorkspaceID
				identity.credentialID = verified.APIKeyHash
				identity.attribution = "validation"
			}
			return result, body, err
		}
	}
	return finishLenientParse(log, statsConn, route, requestLogID, body, withLater)
}

func finishLenientParse[T any](
	log io.Writer,
	statsConn *responseStatsConn,
	route string,
	requestLogID string,
	body []byte,
	parse func([]byte) (T, error),
) (T, []byte, error) {
	lenientResult, dropped, parsedBody, lenientErr := adapter.LenientParse(body, true, parse)
	if lenientErr != nil {
		return lenientResult, body, lenientErr
	}
	statsConn.SetIgnoredParameters(dropped)
	if log != nil {
		// Parameter names are client-chosen strings, so only the count is
		// logged. The names go back to the client alone, in the response header.
		fmt.Fprintf(log, "enclave.lenient_drop request_log_id=%q route=%q count=%d\n",
			requestLogID, route, len(dropped))
	}
	return lenientResult, parsedBody, nil
}

// laterChatChecks mirrors what adapter.ToAnthropic refuses that the parse
// does not: a tool_choice object that is not a function. It reads the parsed
// request, after web search normalization turned a hosted search choice into
// the gateway's own function. Unsupported tools are already refused by the
// parse, by index. TrustedRouter orchestration choices, which their handlers
// consume first, pass.
func laterChatChecks(req *types.OpenAIChatRequest) error {
	if req == nil {
		return nil
	}
	choice, ok := req.ToolChoice.(map[string]any)
	if !ok {
		return nil
	}
	// Compared exactly as adapter.AnthropicToolChoiceFromChat compares it.
	choiceType, _ := choice["type"].(string)
	if choiceType == "function" || strings.HasPrefix(strings.TrimSpace(choiceType), "trustedrouter:") {
		return nil
	}
	return &adapter.AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tool_choice"}
}

const maxIgnoredParametersHeaderBytes = 1024

// ignoredParametersHeaderValue renders dropped paths as one header-safe value.
// Names are client-chosen, so bytes outside printable ASCII become "?" and the
// list is cut at a fixed size, ending in "..." when it is.
func ignoredParametersHeaderValue(dropped []string) string {
	var b strings.Builder
	for i, path := range dropped {
		var clean strings.Builder
		for _, r := range path {
			if r < 0x20 || r > 0x7e || r == ',' {
				clean.WriteByte('?')
				continue
			}
			clean.WriteRune(r)
		}
		item := clean.String()
		separator := ""
		if i > 0 {
			separator = ", "
		}
		if b.Len()+len(separator)+len(item) > maxIgnoredParametersHeaderBytes {
			b.WriteString(separator + "...")
			break
		}
		b.WriteString(separator + item)
	}
	return b.String()
}
