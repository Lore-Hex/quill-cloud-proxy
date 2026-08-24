// Package authcache bounds short-lived negative credential verdicts inside the
// enclave. Callers must key the cache with trustedrouter.LookupHash output;
// raw bearer credentials never belong here.
package authcache

import (
	"container/list"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const (
	// DefaultTTL is deliberately short: it absorbs repeated random-key probes
	// without making a genuine revoke/unrevoke administrative action linger.
	DefaultTTL = 45 * time.Second
	// DefaultMaxEntries caps attacker-controlled lookup hashes at a predictable
	// memory cost. Pressure evicts the least-recently-used verdict; it never
	// turns the cache into an unbounded table or bypasses new verdicts.
	DefaultMaxEntries = 65_536
)

type entry struct {
	lookupHash string
	expiresAt  time.Time
}

// Cache is a concurrency-safe TTL cache with an LRU pressure bound.
type Cache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]*list.Element
	lru        *list.List
}

func New(ttl time.Duration, maxEntries int) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Cache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]*list.Element, maxEntries),
		lru:        list.New(),
	}
}

// Contains reports whether lookupHash has a live definitive-negative verdict.
func (c *Cache) Contains(lookupHash string, now time.Time) bool {
	if c == nil || !isLookupHash(lookupHash) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[lookupHash]
	if !ok {
		return false
	}
	item := element.Value.(*entry)
	if !now.Before(item.expiresAt) {
		c.remove(element)
		return false
	}
	c.lru.MoveToFront(element)
	return true
}

// Remember stores err only when it is a definitive invalid-credential verdict
// and lookupHash has the exact one-way digest shape. Keeping both checks inside
// the cache makes it impossible for a caller to accidentally persist a
// transient failure or a raw bearer. It reports whether a verdict was stored.
func (c *Cache) Remember(lookupHash string, err error, now time.Time) bool {
	if c == nil || !isLookupHash(lookupHash) || !IsDefinitiveInvalidCredential(err) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.entries[lookupHash]; ok {
		item := element.Value.(*entry)
		item.expiresAt = now.Add(c.ttl)
		c.lru.MoveToFront(element)
		return true
	}
	for len(c.entries) >= c.maxEntries {
		c.remove(c.lru.Back())
	}
	element := c.lru.PushFront(&entry{lookupHash: lookupHash, expiresAt: now.Add(c.ttl)})
	c.entries[lookupHash] = element
	return true
}

func isLookupHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// Len returns resident occupancy. Expired entries remain bounded and are
// removed on access or pressure, so this is the operator-relevant memory count.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) remove(element *list.Element) {
	if element == nil {
		return
	}
	item := element.Value.(*entry)
	delete(c.entries, item.lookupHash)
	c.lru.Remove(element)
}

// IsDefinitiveInvalidCredential is intentionally narrow. Only control-plane
// verdicts that explicitly name an invalid, unknown, or revoked API key are
// safe to remember. A status alone is insufficient: a bare 401 can mean a
// broken enclave-to-control-plane credential, while quota, billing, timeouts,
// cancellation, network errors, 429s, and 5xx can all affect a valid customer.
func IsDefinitiveInvalidCredential(err error) bool {
	var controlErr *trustedrouter.ControlPlaneError
	if !errors.As(err, &controlErr) {
		return false
	}
	if controlErr.StatusCode != http.StatusUnauthorized && controlErr.StatusCode != http.StatusForbidden {
		return false
	}
	// EXACTLY the control plane's ErrorType.INVALID_API_KEY and nothing else.
	// This string is a WIRE CONTRACT: quill-router emits it at every
	// bad-customer-key site in the internal gateway and pins it with
	// tests/test_gateway_error_taxonomy.py; the test below pins this side.
	// The earlier draft allowlisted five plausible spellings -- none of which
	// the control plane has ever emitted, so the cache would have been
	// "configured, healthy, and empty": never firing, never noticed. A generic
	// "unauthorized" 401 stays UNCACHED on purpose -- the plane also says that
	// when the ENCLAVE'S OWN internal credential is broken, and caching it
	// would turn one auth misconfiguration into every customer locked out.
	switch strings.ToLower(strings.TrimSpace(controlErr.Type)) {
	case "invalid_api_key":
		return true
	default:
		return false
	}
}
