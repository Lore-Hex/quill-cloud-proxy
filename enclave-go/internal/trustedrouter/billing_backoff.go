package trustedrouter

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DefaultBillingBackoffTTL = 5 * time.Second
const DefaultBillingBackoffMaxEntries = 4096

// BillingBackoff holds only credential/request digests, audit identifiers and
// the router error needed to reproduce a response. Expiry order bounds memory and evicts expired entries first.
type BillingBackoff struct {
	mu           sync.Mutex
	ttl          time.Duration
	maxEntries   int
	entries      map[BillingBackoffKey]*list.Element
	byCredential map[string]map[BillingBackoffKey]struct{}
	order        *list.List
}

// BillingBackoffKey identifies one exact request on one credential. The body
// and header inputs are hashed synchronously and never retained. Length framing
// separates all fields; callers supply canonical header groups in a fixed order.
type BillingBackoffKey struct {
	lookupHash    string
	requestDigest [sha256.Size]byte
}

func NewBillingBackoffKey(lookupHash, method, route string, body []byte, headerGroups ...[]byte) BillingBackoffKey {
	h := sha256.New()
	var size [8]byte
	for _, field := range append([][]byte{[]byte(method), []byte(route), body}, headerGroups...) {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(field)
	}
	key := BillingBackoffKey{lookupHash: lookupHash}
	copy(key.requestDigest[:], h.Sum(nil))
	return key
}

type BillingRejection struct {
	Error     ControlPlaneError
	RequestID string
}

type billingEntry struct {
	key          BillingBackoffKey
	credentialID string
	rejection    BillingRejection
	expiresAt    time.Time
	suppressed   uint64
}

func billingBackoffFromEnv() *BillingBackoff {
	ttl := DefaultBillingBackoffTTL
	if value := strings.TrimSpace(os.Getenv("QUILL_BILLING_402_BACKOFF_MS")); value != "" {
		if ms, err := strconv.ParseInt(value, 10, 64); err == nil && ms >= 0 && ms <= int64((1<<63-1)/time.Millisecond) {
			ttl = time.Duration(ms) * time.Millisecond
		}
	}
	return NewBillingBackoff(ttl, DefaultBillingBackoffMaxEntries)
}

func NewBillingBackoff(ttl time.Duration, maxEntries int) *BillingBackoff {
	if maxEntries <= 0 {
		maxEntries = DefaultBillingBackoffMaxEntries
	}
	return &BillingBackoff{ttl: ttl, maxEntries: maxEntries, entries: make(map[BillingBackoffKey]*list.Element), byCredential: make(map[string]map[BillingBackoffKey]struct{}), order: list.New()}
}

func (c *Client) BillingBackoff() *BillingBackoff {
	if c == nil {
		return nil
	}
	return c.billingBackoff
}

// IsInsufficientCredits accepts only the authorize endpoint's precise taxonomy.
func IsInsufficientCredits(err error) bool {
	var e *ControlPlaneError
	return errors.As(err, &e) && e != nil && e.Path == "/internal/gateway/authorize" && e.StatusCode == 402 && e.Type == "insufficient_credits"
}

// Get never extends expiry. Idempotent requests bypass both reads and writes.
func (c *BillingBackoff) Get(key BillingBackoffKey, idempotent bool, now time.Time) (BillingRejection, bool) {
	if c == nil || c.ttl <= 0 {
		return BillingRejection{}, false
	}
	c.mu.Lock()
	summaries := c.expire(now, nil)
	var rejection BillingRejection
	hit := false
	if !idempotent {
		if element := c.entries[key]; element != nil {
			item := element.Value.(*billingEntry)
			item.suppressed++
			rejection, hit = item.rejection, true
		}
	}
	c.mu.Unlock()
	writeBillingSummaries(summaries)
	return rejection, hit
}

func (c *BillingBackoff) Remember(key BillingBackoffKey, credentialID, requestID string, idempotent bool, err error, now time.Time) bool {
	if c == nil || c.ttl <= 0 || idempotent || !IsInsufficientCredits(err) {
		return false
	}
	digest, decodeErr := hex.DecodeString(key.lookupHash)
	if decodeErr != nil || len(digest) != 32 || key.lookupHash != strings.ToLower(key.lookupHash) {
		return false
	}
	var e *ControlPlaneError
	if !errors.As(err, &e) {
		return false
	}
	c.mu.Lock()
	summaries := c.expire(now, nil)
	defer func() {
		c.mu.Unlock()
		writeBillingSummaries(summaries)
	}()
	// Concurrent denials must not reset an already-open window either.
	if c.entries[key] != nil {
		return false
	}
	for len(c.entries) >= c.maxEntries {
		summaries = c.remove(c.order.Front(), summaries)
	}
	item := &billingEntry{key: key, credentialID: credentialID, expiresAt: now.Add(c.ttl), rejection: BillingRejection{
		// Never retain the raw router body: only fields used by the public renderer.
		Error: ControlPlaneError{Path: e.Path, StatusCode: e.StatusCode, Type: e.Type, Message: e.Message, RetryAfter: e.RetryAfter}, RequestID: requestID,
	}}
	if c.byCredential[key.lookupHash] == nil {
		c.byCredential[key.lookupHash] = make(map[BillingBackoffKey]struct{})
	}
	c.byCredential[key.lookupHash][key] = struct{}{}
	// Callers timestamp the verdict before taking this lock. Concurrent callers
	// can acquire the lock in a different order; keep expiry order exact so an
	// older entry can never hide behind a newer, still-live one.
	for element := c.order.Back(); element != nil; element = element.Prev() {
		if !item.expiresAt.Before(element.Value.(*billingEntry).expiresAt) {
			c.entries[key] = c.order.InsertAfter(item, element)
			return true
		}
	}
	c.entries[key] = c.order.PushFront(item)
	return true
}

func (c *BillingBackoff) expire(now time.Time, summaries []string) []string {
	for element := c.order.Front(); element != nil; element = c.order.Front() {
		if now.Before(element.Value.(*billingEntry).expiresAt) {
			break
		}
		summaries = c.remove(element, summaries)
	}
	return summaries
}

// remove returns the window summary instead of writing it: stderr must never be
// written while c.mu is held, because every inference request takes this lock.
// A window that suppressed nothing adds no line (its request_end already exists).
func (c *BillingBackoff) remove(element *list.Element, summaries []string) []string {
	item := element.Value.(*billingEntry)
	if item.suppressed > 0 {
		summaries = append(summaries, fmt.Sprintf("enclave.billing_402_backoff credential_id=%q credential_fingerprint=%q suppressed=%d window_ms=%d\n", item.credentialID, item.key.lookupHash, item.suppressed, c.ttl.Milliseconds()))
	}
	delete(c.entries, item.key)
	delete(c.byCredential[item.key.lookupHash], item.key)
	if len(c.byCredential[item.key.lookupHash]) == 0 {
		delete(c.byCredential, item.key.lookupHash)
	}
	c.order.Remove(element)
	return summaries
}

func writeBillingSummaries(summaries []string) {
	for _, line := range summaries {
		fmt.Fprint(os.Stderr, line)
	}
}

// SetCredentialID attaches the identity resolved by the ordinary audit path.
// RequestID prevents a late lookup from modifying a subsequent window.
func (c *BillingBackoff) SetCredentialID(key BillingBackoffKey, requestID, credentialID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[key]; element != nil {
		item := element.Value.(*billingEntry)
		if item.rejection.RequestID == requestID {
			item.credentialID = credentialID
		}
	}
}

// ForgetCredential drops only this credential's indexed entries, without a scan.
// As with expiry/eviction, summaries are emitted only after releasing the lock.
func (c *BillingBackoff) ForgetCredential(lookupHash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	var summaries []string
	for key := range c.byCredential[lookupHash] {
		summaries = c.remove(c.entries[key], summaries)
	}
	c.mu.Unlock()
	writeBillingSummaries(summaries)
}
