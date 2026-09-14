package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/phalaaci"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"golang.org/x/crypto/sha3"
)

func phalaJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := phalaaci.CanonicalValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func phalaSign(t *testing.T, key *secp256k1.PrivateKey, message []byte) string {
	t.Helper()
	hash := sha3.NewLegacyKeccak256()
	hash.Write(message)
	sig := ecdsa.SignCompact(key, hash.Sum(nil), true)
	raw := append([]byte{}, sig[1:]...)
	raw = append(raw, sig[0]-27-4)
	return hex.EncodeToString(raw)
}

func phalaFixture(t *testing.T) (*phalaVerifier, phalaaci.VerificationRequest) {
	t.Helper()
	now := time.Unix(1750000000, 0)
	appID := strings.Repeat("a", 40)
	appBytes, _ := hex.DecodeString(appID)
	root, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	app, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issued := append([]byte("dstack-kms-issued:"), appBytes...)
	issued = append(issued, app.PubKey().SerializeCompressed()...)
	appSignature := phalaSign(t, root, issued)
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := phalaaci.Keyset{NotAfter: now.Unix() + 300, ReceiptKeys: []phalaaci.Key{{ID: "receipt", Algo: "ed25519", PublicKey: strings.Repeat("b", 64)}}, EncryptionKeys: []phalaaci.Key{{ID: "enc", Algo: phalaaci.Suite, PublicKey: hex.EncodeToString(xKey.PublicKey().Bytes())}}}
	// Synthetic data, never a deployable release approval.
	var keyObject map[string]any
	json.Unmarshal(phalaJSON(t, keys), &keyObject)
	keyObject["tls_public_keys"] = []any{map[string]any{"domain": "api.redpill.ai", "spki_sha256": strings.Repeat("c", 64)}}
	custodyKeys := []any{}
	for _, key := range append(keys.ReceiptKeys, keys.EncryptionKeys...) {
		kms, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		purpose, path, role := "aci.receipt.ed25519.v1", "aci/receipt-ed25519/v1", "receipt"
		if key.Algo == phalaaci.Suite {
			purpose, path, role = "aci.e2ee.x25519.v1", "aci/e2ee-x25519/v1", "e2ee-x25519"
		}
		pub := hex.EncodeToString(kms.PubKey().SerializeCompressed())
		custodyKeys = append(custodyKeys, map[string]any{"role": role, "path": path, "purpose": purpose, "algo": key.Algo, "public_key": key.PublicKey, "kms_public_key": pub, "signature_chain": []string{phalaSign(t, app, []byte(purpose+":"+pub)), appSignature}})
	}
	compose := `{"docker_compose_file":"synthetic reviewed workload"}`
	osHash := strings.Repeat("d", 64)
	events := []nearAIRuntimeEvent{{IMR: 3, EventType: 0x08000001, Event: "app-id", EventPayload: appID}, {IMR: 3, EventType: 0x08000001, Event: "compose-hash", EventPayload: phalaaci.Hex([]byte(compose))}, {IMR: 3, EventType: 0x08000001, Event: "os-image-hash", EventPayload: osHash}, {IMR: 3, EventType: 0x08000001, Event: "system-ready"}}
	rtmr, err := replayNearAIRuntimeEvents(events, phalaaci.Hex([]byte(compose)), osHash)
	if err != nil {
		t.Fatal(err)
	}
	digest := phalaaci.Hash(phalaJSON(t, keyObject))
	nonce := strings.Repeat("f", 64)
	statement := phalaJSON(t, map[string]any{"keyset_digest": digest, "nonce": nonce, "purpose": "aci.report_data.v1"})
	reportData, _ := hex.DecodeString(phalaaci.Hex(statement))
	reportData = append(reportData, make([]byte, 32)...)
	boot := &nearAIBootMeasurements{MRTD: strings.Repeat("0", 96), RTMR0: strings.Repeat("0", 96), RTMR1: strings.Repeat("0", 96), RTMR2: strings.Repeat("0", 96)}
	verifier := &phalaVerifier{now: func() time.Time { return now }, policies: []phalaPolicy{{Domain: "api.redpill.ai", Models: []string{"model"}, ComposeHash: phalaaci.Hex([]byte(compose)), OSImageHash: osHash, Boot: boot, KMSRoot: hex.EncodeToString(root.PubKey().SerializeCompressed()), Review: "TEST ONLY", UpstreamVerifiers: []string{"reviewed"}}}, quote: func(string) (*tdxpb.TDQuoteBody, error) {
		return &tdxpb.TDQuoteBody{ReportData: reportData, MrTd: make([]byte, 48), Rtmrs: [][]byte{make([]byte, 48), make([]byte, 48), make([]byte, 48), rtmr}}, nil
	}}
	report := map[string]any{"api_version": "aci/1", "workload_keyset_digest": digest, "service_capabilities": map[string]any{"supported_e2ee_versions": []string{"2"}}, "attestation": map[string]any{"tee_type": "tdx", "report_data": phalaaci.Hex(statement), "workload_keyset": keyObject, "evidence": map[string]any{"quote": "synthetic", "app_compose": compose, "event_log": string(phalaJSON(t, events)), "key_custody": map[string]any{"provider": "dstack-kms", "keys": custodyKeys}}}}
	return verifier, phalaaci.VerificationRequest{Domain: "api.redpill.ai", Model: "model", Nonce: nonce, Fingerprint: strings.Repeat("c", 64), Report: phalaJSON(t, report)}
}

func TestPhalaVerifierRequiresEveryTrustAnchor(t *testing.T) {
	for _, change := range []string{"good", "unreviewed", "model", "tls", "nonce", "boot", "kms-root", "compose", "event-payload", "missing-custody", "wrong-role", "wrong-purpose", "wrong-path", "missing-chain", "bad-signature", "wrong-app", "missing-encryption-custody", "duplicate-custody"} {
		t.Run(change, func(t *testing.T) {
			v, r := phalaFixture(t)
			var report map[string]any
			json.Unmarshal(r.Report, &report)
			ev := report["attestation"].(map[string]any)["evidence"].(map[string]any)
			custody := ev["key_custody"].(map[string]any)
			keys := custody["keys"].([]any)
			switch change {
			case "unreviewed":
				v.policies = nil
			case "model":
				r.Model = "other"
			case "tls":
				r.Fingerprint = strings.Repeat("d", 64)
			case "nonce":
				r.Nonce = strings.Repeat("e", 64)
			case "boot":
				v.policies[0].Boot.MRTD = strings.Repeat("1", 96)
			case "kms-root":
				v.policies[0].KMSRoot = strings.Repeat("a", 66)
			case "compose":
				ev["app_compose"] = "changed"
			case "event-payload":
				ev["event_log"] = strings.Replace(ev["event_log"].(string), "system-ready", "other", 1)
			case "missing-custody":
				delete(ev, "key_custody")
			case "wrong-role":
				keys[0].(map[string]any)["role"] = "enc"
			case "wrong-purpose":
				keys[0].(map[string]any)["purpose"] = "unrelated"
			case "wrong-path":
				keys[0].(map[string]any)["path"] = "unrelated"
			case "missing-chain":
				keys[0].(map[string]any)["signature_chain"] = []any{}
			case "bad-signature":
				keys[0].(map[string]any)["signature_chain"].([]any)[0] = strings.Repeat("0", 130)
			case "wrong-app":
				ev["event_log"] = strings.Replace(ev["event_log"].(string), strings.Repeat("a", 40), strings.Repeat("b", 40), 1)
			case "missing-encryption-custody":
				custody["keys"] = keys[:1]
			case "duplicate-custody":
				custody["keys"] = append(keys, keys[0])
			}
			r.Report = phalaJSON(t, report)
			proof, err := v.verify(r)
			if change == "good" {
				if err != nil || proof.Policy != phalaaci.PolicyName || !proof.ExpiresAt.Equal(v.now().Add(2*time.Minute)) {
					t.Fatalf("valid synthetic proof rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("missing trust anchor accepted")
			}
		})
	}
}

func TestPhalaProductionPolicyIsNotTOFU(t *testing.T) {
	v, err := newPhalaVerifier()
	if err != nil {
		t.Fatal(err)
	}
	// Until independently reviewed policy is committed, production must stay
	// disabled. Do not replace this fixture with hashes copied from a report.
	if len(v.policies) != 0 {
		t.Skip("production policy now requires its own reviewed vectors")
	}
	_, r := phalaFixture(t)
	v.now = func() time.Time { return time.Unix(1750000000, 0) }
	if _, err := v.verify(r); err == nil {
		t.Fatal("unreviewed release accepted")
	}
}
