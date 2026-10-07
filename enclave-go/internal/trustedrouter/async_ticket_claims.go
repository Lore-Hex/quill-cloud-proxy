package trustedrouter

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // UUIDv5 compatibility; not a security digest.
	"encoding/hex"
	"encoding/json"
	"regexp"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
)

var ticketIdentity = regexp.MustCompile(`^[A-Za-z0-9_./:@+\-]+$`)
var ticketNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var ticketDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Keep the claim schema separate from TerminalEnvelope: embedding it here
// would silently admit terminal-only fields into the signed ticket.
type asyncTicketClaims struct {
	AuthorizationID  string `json:"authorization_id"`
	GenerationID     string `json:"generation_id"`
	WorkspaceID      string `json:"workspace_id"`
	KeyID            string `json:"key_id"`
	InvocationNonce  string `json:"invocation_nonce"`
	BillingAuthority string `json:"billing_authority"`
	JournalRegion    string `json:"journal_region"`
	Epoch            int64  `json:"epoch"`
	SnapshotVersion  int64  `json:"snapshot_version"`
	SnapshotHash     string `json:"snapshot_hash"`
	RouteType        string `json:"route_type"`
	Streamed         bool   `json:"streamed"`
	Reservation      string `json:"reservation_id"`
	Origin           string `json:"settle_origin"`
	Eligible         bool   `json:"async_eligible"`
	Iss              string `json:"iss"`
	Aud              string `json:"aud"`
	Iat              int64  `json:"iat"`
	Exp              int64  `json:"exp"`
}

func parseAsyncTicketClaims(raw []byte, now int64) (asyncTicketClaims, bool) {
	var c asyncTicketClaims
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&fields) != nil {
		return c, false
	}
	names := []string{"authorization_id", "generation_id", "workspace_id", "key_id", "invocation_nonce", "billing_authority", "journal_region", "epoch", "snapshot_version", "snapshot_hash", "route_type", "streamed", "reservation_id", "settle_origin", "async_eligible", "iss", "aud", "iat", "exp"}
	if len(fields) != len(names) {
		return c, false
	}
	for _, name := range names {
		if fields[name] == nil {
			return c, false
		}
	}
	// The compact verifier already restricts the wire to unescaped ASCII and
	// int64 integers. On that domain Marshal matches Python's sorted, compact,
	// ensure_ascii JSON exactly, without rounding integers through float64.
	canonical, err := json.Marshal(fields)
	if err != nil || !bytes.Equal(canonical, raw) {
		return c, false
	}
	if json.Unmarshal(raw, &c) != nil {
		return c, false
	}
	for _, value := range []string{c.AuthorizationID, c.WorkspaceID, c.KeyID, c.Reservation} {
		if len(value) > 64 || !ticketIdentity.MatchString(value) {
			return c, false
		}
	}
	for _, value := range []string{c.GenerationID, c.JournalRegion, c.Iss, c.Aud} {
		if len(value) > 512 || !ticketIdentity.MatchString(value) {
			return c, false
		}
	}
	if !ticketNonce.MatchString(c.InvocationNonce) || !ticketDigest.MatchString(c.SnapshotHash) || c.BillingAuthority != "local" || c.Origin != "typed" || !asyncCohort(c.RouteType) || c.SnapshotVersion != 1 || c.Epoch < 1 || c.Iat < 0 || c.Exp < 0 {
		return c, false
	}
	if c.Iat > now || now >= c.Exp || c.Exp <= c.Iat || c.Exp-c.Iat > 300 {
		return c, false
	}
	if c.GenerationID != ticketGenerationID(c.AuthorizationID) {
		return c, false
	}
	return c, true
}

func ticketGenerationID(authorizationID string) string {
	// uuid.NAMESPACE_URL, followed by the router's name, hashed with UUIDv5.
	namespace := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	sum := sha1.Sum(append(namespace, []byte("trustedrouter:"+authorizationID)...)) //nolint:gosec // UUIDv5 compatibility; not a security digest.
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return "gen-" + hex.EncodeToString(sum[:16])
}

func (c asyncTicketClaims) terminal() billingv1.TerminalEnvelope {
	return billingv1.TerminalEnvelope{AuthorizationID: c.AuthorizationID, GenerationID: c.GenerationID, WorkspaceID: c.WorkspaceID, KeyID: c.KeyID, InvocationNonce: c.InvocationNonce, BillingAuthority: c.BillingAuthority, JournalRegion: c.JournalRegion, Epoch: c.Epoch, SnapshotVersion: c.SnapshotVersion, SnapshotHash: c.SnapshotHash, RouteType: c.RouteType, Streamed: c.Streamed}
}
