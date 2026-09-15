// Package phalaaci implements the bounded ACI/1 and E2EE v2 wire contracts.
// Hardware verification and independently reviewed release policy live in the
// attestation sidecar. A valid signature alone is not a trust decision.
package phalaaci

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const MaxArtifactBytes = 8 << 20
const PolicyName = "phala-aci-reviewed-v1"

type Key struct {
	ID        string `json:"key_id"`
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

type Keyset struct {
	NotAfter       int64 `json:"not_after"`
	ReceiptKeys    []Key `json:"receipt_signing_keys"`
	EncryptionKeys []Key `json:"e2ee_public_keys"`
	TLSKeys        []struct {
		Domain string `json:"domain"`
		SPKI   string `json:"spki_sha256"`
	} `json:"tls_public_keys"`
}

type Report struct {
	Version     string `json:"api_version"`
	Digest      string `json:"workload_keyset_digest"`
	Attestation struct {
		TEE        string          `json:"tee_type"`
		ReportData string          `json:"report_data"`
		Keyset     json.RawMessage `json:"workload_keyset"`
		Evidence   json.RawMessage `json:"evidence"`
	} `json:"attestation"`
	Capabilities struct {
		Versions []string `json:"supported_e2ee_versions"`
	} `json:"service_capabilities"`
}

// VerificationRequest contains public attestation material only, never API keys
// or prompts. The caller must observe the TLS fingerprint on its own connection.
type VerificationRequest struct {
	Domain      string          `json:"domain"`
	Model       string          `json:"model"`
	Nonce       string          `json:"nonce"`
	Fingerprint string          `json:"tls_fingerprint"`
	Report      json.RawMessage `json:"report"`
}

type Proof struct {
	Policy            string    `json:"policy"`
	Domain            string    `json:"domain"`
	Model             string    `json:"model"`
	Fingerprint       string    `json:"tls_fingerprint"`
	VerifiedAt        time.Time `json:"verified_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Keyset            Keyset    `json:"keyset"`
	Digest            string    `json:"digest"`
	UpstreamVerifiers []string  `json:"upstream_verifiers"`
}

func Hash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func Hex(raw []byte) string { return strings.TrimPrefix(Hash(raw), "sha256:") }

func Canonical(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes || !json.Valid(raw) {
		return nil, errors.New("ACI JSON size invalid")
	}
	// RFC 8785 also rejects duplicate members and invalid Unicode, preventing
	// different decoders from verifying one identity and using another.
	// The library accepts object/array roots only; wrapping one validated
	// value supports scalar message content without inventing a serializer.
	wrapped := append([]byte{'['}, raw...)
	wrapped = append(wrapped, ']')
	canonical, err := jsoncanonicalizer.Transform(wrapped)
	if err != nil {
		return nil, err
	}
	return canonical[1 : len(canonical)-1], nil
}

func CanonicalValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return Canonical(raw)
}

func Decode(raw []byte, value any) error {
	if _, err := Canonical(raw); err != nil {
		return errors.New("invalid ACI JSON")
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return errors.New("invalid ACI document shape")
	}
	return nil
}

func IsHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && value == strings.ToLower(value)
}

func BindReport(request VerificationRequest, now time.Time) (*Report, *Keyset, error) {
	if !IsHex(request.Nonce, 32) || !IsHex(request.Fingerprint, 32) {
		return nil, nil, errors.New("invalid ACI challenge or TLS fingerprint")
	}
	var report Report
	if err := Decode(request.Report, &report); err != nil {
		return nil, nil, err
	}
	keyBytes, err := Canonical(report.Attestation.Keyset)
	if err != nil {
		return nil, nil, err
	}
	digest := Hash(keyBytes)
	statement := []byte(fmt.Sprintf(`{"keyset_digest":"%s","nonce":"%s","purpose":"aci.report_data.v1"}`, digest, request.Nonce))
	if report.Version != "aci/1" || report.Attestation.TEE != "tdx" ||
		report.Digest != digest || report.Attestation.ReportData != Hex(statement) {
		return nil, nil, errors.New("ACI report challenge/keyset binding failed")
	}
	var keys Keyset
	if err := Decode(keyBytes, &keys); err != nil {
		return nil, nil, err
	}
	if now.Unix() >= keys.NotAfter {
		return nil, nil, errors.New("ACI keyset expired")
	}
	supported := false
	for _, version := range report.Capabilities.Versions {
		supported = supported || version == "2"
	}
	if !supported {
		return nil, nil, errors.New("ACI E2EE v2 not supported")
	}
	matched := false
	for _, key := range keys.TLSKeys {
		matched = matched || key.Domain == request.Domain && key.SPKI == request.Fingerprint
	}
	if !matched {
		return nil, nil, errors.New("ACI TLS peer is not in the attested keyset")
	}
	return &report, &keys, nil
}

type Session struct {
	Version     string `json:"api_version"`
	Verifier    string `json:"verifier_id"`
	Upstream    string `json:"upstream_name"`
	Established int64  `json:"established_at"`
	Expires     int64  `json:"expires_at"`
	Evidence    struct {
		Digest string `json:"digest"`
		Data   string `json:"data"`
	} `json:"evidence"`
	Bindings []struct {
		Type   string `json:"type"`
		Origin string `json:"origin"`
		SPKI   string `json:"spki_sha256"`
	} `json:"channel_binding"`
	Endpoint string `json:"endpoint"`
}

// VerifySession checks immutable evidence publication. Its hardware appraisal
// is delegated to the independently reviewed, quote-pinned aggregator release,
// not to arbitrary claims supplied by a session. Unknown verifiers fail closed.
func VerifySession(raw []byte, id string, proof *Proof, now time.Time) (*Session, error) {
	if !IsHex(id, 32) || Hex(raw) != id {
		return nil, errors.New("ACI session content address mismatch")
	}
	var session Session
	if err := Decode(raw, &session); err != nil {
		return nil, err
	}
	allowed := false
	for _, verifier := range proof.UpstreamVerifiers {
		allowed = allowed || verifier == session.Verifier
	}
	if !allowed || session.Version != "aci/1" || session.Upstream == "" ||
		session.Established > now.Unix() || session.Expires <= now.Unix() || session.Expires <= session.Established {
		return nil, errors.New("ACI session expired or verifier not reviewed")
	}
	const prefix = "data:application/json;base64,"
	if !strings.HasPrefix(session.Evidence.Data, prefix) {
		return nil, errors.New("ACI upstream evidence is missing")
	}
	evidence, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(session.Evidence.Data, prefix))
	if err != nil || Hash(evidence) != session.Evidence.Digest {
		return nil, errors.New("ACI upstream evidence digest mismatch")
	}
	var object map[string]json.RawMessage
	if err := Decode(evidence, &object); err != nil || len(object) == 0 {
		return nil, errors.New("ACI upstream evidence is empty or malformed")
	}
	bound := false
	for _, binding := range session.Bindings {
		bound = bound || binding.Type == "tls_spki_sha256" && binding.Origin == session.Endpoint &&
			strings.HasPrefix(binding.Origin, "https://") && IsHex(binding.SPKI, 32)
	}
	if !bound {
		return nil, errors.New("ACI upstream has no reviewed TLS channel binding")
	}
	return &session, nil
}

type Receipt struct {
	Version   string `json:"api_version"`
	ID        string `json:"receipt_id"`
	ChatID    string `json:"chat_id"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
	Digest    string `json:"workload_keyset_digest"`
	Model     string `json:"model"`
	Method    string `json:"method"`
	Endpoint  string `json:"endpoint"`
	ServedAt  int64  `json:"served_at"`
	Events    []struct {
		Type      string `json:"type"`
		BodyHash  string `json:"body_hash"`
		Required  bool   `json:"required"`
		Result    string `json:"result"`
		SessionID string `json:"session_id"`
		ModelID   string `json:"model_id"`
		RouteID   string `json:"target_route_id"`
	} `json:"event_log"`
}

type Exchange struct {
	ReceiptID    string
	ChatID       string
	RequestHash  string
	ResponseHash string
	StartedAt    time.Time
	SessionID    string
	Session      *Session
}

func VerifyReceipt(raw []byte, proof *Proof, exchange Exchange, now time.Time) error {
	var receipt Receipt
	if err := Decode(raw, &receipt); err != nil {
		return err
	}
	if receipt.Version != "aci/1" || receipt.ID != exchange.ReceiptID || receipt.ChatID != exchange.ChatID ||
		receipt.Digest != proof.Digest || receipt.Model != proof.Model || receipt.Method != "POST" ||
		receipt.Endpoint != "/v1/chat/completions" || receipt.ServedAt < exchange.StartedAt.Unix()-5 ||
		receipt.ServedAt > now.Unix()+5 || receipt.ServedAt >= proof.Keyset.NotAfter {
		return errors.New("ACI receipt context mismatch")
	}
	var unsigned map[string]json.RawMessage
	if err := Decode(raw, &unsigned); err != nil {
		return err
	}
	delete(unsigned, "signature")
	message, err := CanonicalValue(unsigned)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return errors.New("ACI receipt signature malformed")
	}
	valid := 0
	for _, key := range proof.Keyset.ReceiptKeys {
		if key.ID != receipt.KeyID {
			continue
		}
		public, err := hex.DecodeString(key.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || key.Algo != "ed25519" ||
			!ed25519.Verify(public, message, signature) {
			return errors.New("ACI receipt signature invalid")
		}
		valid++
	}
	if valid != 1 {
		return errors.New("ACI receipt signing key absent or ambiguous")
	}
	seen := map[string]bool{}
	for _, event := range receipt.Events {
		if seen[event.Type] {
			return errors.New("ACI receipt duplicate events")
		}
		seen[event.Type] = true
		switch event.Type {
		case "request.received":
			if event.BodyHash != exchange.RequestHash {
				return errors.New("ACI receipt request hash mismatch")
			}
		case "response.returned":
			if event.BodyHash != exchange.ResponseHash {
				return errors.New("ACI receipt response hash mismatch")
			}
		case "upstream.verified":
			if !event.Required || event.Result != "verified" || event.SessionID != exchange.SessionID || event.ModelID != proof.Model {
				return errors.New("ACI receipt upstream/model mismatch")
			}
		case "route.selected":
			if exchange.Session == nil || event.RouteID != exchange.Session.Upstream+":"+proof.Model {
				return errors.New("ACI receipt selected route mismatch")
			}
		}
	}
	for _, required := range []string{"request.received", "response.returned", "upstream.verified", "route.selected"} {
		if !seen[required] {
			return errors.New("ACI receipt required event missing")
		}
	}
	if exchange.Session == nil || receipt.ServedAt < exchange.Session.Established || receipt.ServedAt >= exchange.Session.Expires {
		return errors.New("ACI receipt used an expired upstream session")
	}
	return nil
}
