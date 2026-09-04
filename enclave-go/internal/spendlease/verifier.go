package spendlease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

var leaseUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type configuredKey struct {
	publicKey ed25519.PublicKey
	notBefore int64
	notAfter  int64
}

type Verifier struct {
	keys map[string]configuredKey
	now  func() time.Time
}

type protectedHeader struct {
	Algorithm string          `json:"alg"`
	Type      string          `json:"typ"`
	KID       string          `json:"kid"`
	JWK       json.RawMessage `json:"jwk"`
}

func NewVerifier(configJSON []byte) (*Verifier, error) {
	var config IssuerConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("spendlease: parse issuer config: %w", err)
	}
	if config.Version != ConfigV1 || len(config.Keys) == 0 {
		return nil, errors.New("spendlease: issuer config must be version 1 with at least one key")
	}
	keys := make(map[string]configuredKey, len(config.Keys))
	for _, item := range config.Keys {
		if item.KID == "" || item.JWK.KeyType != "OKP" || item.JWK.Curve != "Ed25519" {
			return nil, errors.New("spendlease: invalid issuer key metadata")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(item.JWK.X)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("spendlease: invalid Ed25519 key for kid %q", item.KID)
		}
		digest := sha256.Sum256(decoded)
		if item.KID != base64.RawURLEncoding.EncodeToString(digest[:]) {
			return nil, fmt.Errorf("spendlease: kid does not match configured public key")
		}
		if item.NotBefore <= 0 || item.NotAfter < item.NotBefore {
			return nil, fmt.Errorf("spendlease: invalid validity window for kid %q", item.KID)
		}
		if _, duplicate := keys[item.KID]; duplicate {
			return nil, fmt.Errorf("spendlease: duplicate issuer kid %q", item.KID)
		}
		keys[item.KID] = configuredKey{append(ed25519.PublicKey(nil), decoded...), item.NotBefore, item.NotAfter}
	}
	return &Verifier{keys: keys, now: time.Now}, nil
}

func (v *Verifier) Verify(token string) (VerifiedLease, error) {
	if v == nil || v.now == nil {
		return VerifiedLease{}, errors.New("spendlease: verifier is not configured")
	}
	return v.VerifyAt(token, v.now())
}

// VerifyAt is exported to make receipt-time/skew boundary tests exact. A
// production caller passes time.Now(), whose monotonic component is retained
// by Deadline through time.Add.
func (v *Verifier) VerifyAt(token string, receivedAt time.Time) (VerifiedLease, error) {
	if v == nil {
		return VerifiedLease{}, errors.New("spendlease: verifier is not configured")
	}
	if strings.HasPrefix(strings.TrimSpace(token), "{") {
		return VerifiedLease{}, errors.New("spendlease: compact JWS required")
	}
	parts, err := receipt.ParseJWS([]byte(token))
	if err != nil {
		return VerifiedLease{}, fmt.Errorf("spendlease: parse JWS: %w", err)
	}
	var header protectedHeader
	if err := json.Unmarshal(parts.ProtectedJSON, &header); err != nil {
		return VerifiedLease{}, fmt.Errorf("spendlease: parse protected header: %w", err)
	}
	if header.Algorithm != "EdDSA" || header.Type != JWSType {
		return VerifiedLease{}, errors.New("spendlease: unsupported protected header")
	}
	key, ok := v.keys[header.KID]
	if !ok {
		return VerifiedLease{}, errors.New("spendlease: unconfigured issuer kid")
	}
	if len(parts.Signature) != ed25519.SignatureSize || !ed25519.Verify(key.publicKey, parts.SigningInput, parts.Signature) {
		return VerifiedLease{}, errors.New("spendlease: signature verification failed")
	}
	var claims Claims
	if err := json.Unmarshal(parts.PayloadJSON, &claims); err != nil {
		return VerifiedLease{}, fmt.Errorf("spendlease: parse claims: %w", err)
	}
	if err := validateClaims(claims, key, receivedAt); err != nil {
		return VerifiedLease{}, err
	}
	wallReceived := time.Unix(receivedAt.Unix(), int64(receivedAt.Nanosecond()))
	deadline := receivedAt.Add(time.Unix(claims.ExpiresAt, 0).Add(Skew).Sub(wallReceived))
	admitUntil := receivedAt.Add(time.Unix(claims.ExpiresAt, 0).Add(-AdmissionMargin).Sub(wallReceived))
	return VerifiedLease{Claims: claims, Deadline: deadline, AdmitUntil: admitUntil}, nil
}

// VerifyShadow is the Stage A authority gate. It deliberately rejects a
// cryptographically valid authoritative token.
func (v *Verifier) VerifyShadow(token string) (VerifiedLease, error) {
	lease, err := v.Verify(token)
	if err != nil {
		return VerifiedLease{}, err
	}
	if lease.Claims.Authoritative {
		return VerifiedLease{}, errors.New("spendlease: authoritative grant refused in Stage A")
	}
	return lease, nil
}

func (v *Verifier) VerifyShadowAt(token string, receivedAt time.Time) (VerifiedLease, error) {
	return v.VerifyForStateAt(token, receivedAt, false)
}

// VerifyForStateAt keeps authoritative grants cryptographically inert unless
// the local-admission flag was measured into this GCP boot. Non-authoritative
// Stage A grants are accepted in either mode.
func (v *Verifier) VerifyForStateAt(token string, receivedAt time.Time, localAdmission bool) (VerifiedLease, error) {
	lease, err := v.VerifyAt(token, receivedAt)
	if err != nil {
		return VerifiedLease{}, err
	}
	if lease.Claims.Authoritative && !localAdmission {
		return VerifiedLease{}, errors.New("spendlease: authoritative grant refused in Stage A")
	}
	return lease, nil
}

func validateClaims(c Claims, key configuredKey, now time.Time) error {
	if c.Version != 1 || c.Type != JWSType || !leaseUUID.MatchString(c.LeaseID) || c.KeyHash == "" || c.WorkspaceID == "" || c.BootKID == "" {
		return errors.New("spendlease: invalid required claims")
	}
	if c.Cohort != Cohort || c.CapMicro <= 0 || c.Generation <= 0 || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return errors.New("spendlease: invalid grant claims")
	}
	if c.LocalAdmissionAllowed && (!c.Authoritative || !sha256Hex.MatchString(c.RoutingPolicyHash)) {
		return errors.New("spendlease: invalid local-admission claims")
	}
	if time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > MaximumTTL {
		return errors.New("spendlease: lease TTL exceeds Stage A maximum")
	}
	if c.IssuedAt < key.notBefore || c.IssuedAt > key.notAfter {
		return errors.New("spendlease: token iat is outside issuer validity window")
	}
	latest := time.Unix(c.ExpiresAt, 0).Add(Skew)
	if now.After(latest) {
		return errors.New("spendlease: token expired")
	}
	if time.Unix(c.IssuedAt, 0).After(now.Add(Skew)) {
		return errors.New("spendlease: token issued in the future")
	}
	if c.Catalog.Version == "" || len(c.Catalog.Candidates) == 0 {
		return errors.New("spendlease: catalog snapshot is empty")
	}
	for _, candidate := range c.Catalog.Candidates {
		if candidate.EndpointID == "" || candidate.Model == "" || candidate.Provider == "" || candidate.RouteType == "" ||
			candidate.InputPriceMicroPerMTok < 0 || candidate.OutputPriceMicroPerMTok < 0 || candidate.RequestPriceMicro < 0 ||
			candidate.CacheReadMicroPerMTok < 0 || candidate.CacheWriteMicroPerMTok < 0 ||
			(candidate.PriceTierMaxInputTokens != nil && *candidate.PriceTierMaxInputTokens < 0) {
			return errors.New("spendlease: invalid catalog candidate")
		}
		if c.LocalAdmissionAllowed && (candidate.UpstreamModel == "" || candidate.UsageType != "Credits") {
			return errors.New("spendlease: invalid local-admission candidate")
		}
	}
	return nil
}
