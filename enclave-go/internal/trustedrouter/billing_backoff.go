package trustedrouter

import (
	"container/list"
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

// BillingBackoff is separate from credential authentication. It holds only a
// lookup digest, audit identifiers and the router error needed to reproduce a
// response. Expiry order bounds memory and evicts expired entries first.
type BillingBackoff struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]*list.Element
	order      *list.List
}

type BillingRejection struct {
	Error     ControlPlaneError
	RequestID string
}

type billingEntry struct {
	lookupHash   string
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
	return &BillingBackoff{ttl: ttl, maxEntries: maxEntries, entries: make(map[string]*list.Element), order: list.New()}
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
func (c *BillingBackoff) Get(lookupHash string, idempotent bool, now time.Time) (BillingRejection, bool) {
	if c == nil || c.ttl <= 0 {
		return BillingRejection{}, false
	}
	c.mu.Lock()
	summaries := c.expire(now, nil)
	var rejection BillingRejection
	hit := false
	if !idempotent {
		if element := c.entries[lookupHash]; element != nil {
			item := element.Value.(*billingEntry)
			item.suppressed++
			rejection, hit = item.rejection, true
		}
	}
	c.mu.Unlock()
	writeBillingSummaries(summaries)
	return rejection, hit
}

func (c *BillingBackoff) Remember(lookupHash, credentialID, requestID string, idempotent bool, err error, now time.Time) bool {
	if c == nil || c.ttl <= 0 || idempotent || !IsInsufficientCredits(err) {
		return false
	}
	digest, decodeErr := hex.DecodeString(lookupHash)
	if decodeErr != nil || len(digest) != 32 || lookupHash != strings.ToLower(lookupHash) {
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
	if c.entries[lookupHash] != nil {
		return false
	}
	for len(c.entries) >= c.maxEntries {
		summaries = c.remove(c.order.Front(), summaries)
	}
	item := &billingEntry{lookupHash: lookupHash, credentialID: credentialID, expiresAt: now.Add(c.ttl), rejection: BillingRejection{
		// Never retain the raw router body: only fields used by the public renderer.
		Error: ControlPlaneError{Path: e.Path, StatusCode: e.StatusCode, Type: e.Type, Message: e.Message, RetryAfter: e.RetryAfter}, RequestID: requestID,
	}}
	// Callers timestamp the verdict before taking this lock. Concurrent callers
	// can acquire the lock in a different order; keep expiry order exact so an
	// older entry can never hide behind a newer, still-live one.
	for element := c.order.Back(); element != nil; element = element.Prev() {
		if !item.expiresAt.Before(element.Value.(*billingEntry).expiresAt) {
			c.entries[lookupHash] = c.order.InsertAfter(item, element)
			return true
		}
	}
	c.entries[lookupHash] = c.order.PushFront(item)
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
		summaries = append(summaries, fmt.Sprintf("enclave.billing_402_backoff credential_id=%q credential_fingerprint=%q suppressed=%d window_ms=%d\n", item.credentialID, item.lookupHash, item.suppressed, c.ttl.Milliseconds()))
	}
	delete(c.entries, item.lookupHash)
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
func (c *BillingBackoff) SetCredentialID(lookupHash, requestID, credentialID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[lookupHash]; element != nil {
		item := element.Value.(*billingEntry)
		if item.rejection.RequestID == requestID {
			item.credentialID = credentialID
		}
	}
}
