package phalaaci

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := CanonicalValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCanonicalRejectsAmbiguousIdentity(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `null trailing`, ``} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Canonical([]byte(raw)); err == nil {
				t.Fatal("accepted ambiguous JSON")
			}
		})
	}
}

func TestReportBindingRejectsTampering(t *testing.T) {
	now := time.Unix(1750000000, 0)
	keys := map[string]any{"not_after": now.Unix() + 60, "tls_public_keys": []any{map[string]any{"domain": "api.redpill.ai", "spki_sha256": strings.Repeat("b", 64)}}}
	keyRaw := mustJSON(t, keys)
	digest := Hash(keyRaw)
	nonce := strings.Repeat("a", 64)
	statement := mustJSON(t, map[string]any{"keyset_digest": digest, "nonce": nonce, "purpose": "aci.report_data.v1"})
	base := map[string]any{"api_version": "aci/1", "workload_keyset_digest": digest,
		"attestation":          map[string]any{"tee_type": "tdx", "report_data": Hex(statement), "workload_keyset": keys},
		"service_capabilities": map[string]any{"supported_e2ee_versions": []string{"2"}}}
	request := VerificationRequest{Domain: "api.redpill.ai", Nonce: nonce, Fingerprint: strings.Repeat("b", 64), Report: mustJSON(t, base)}
	if _, _, err := BindReport(request, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"nonce", "fingerprint", "domain", "expired", "keyset", "version"} {
		t.Run(change, func(t *testing.T) {
			r := request
			clock := now
			switch change {
			case "nonce":
				r.Nonce = strings.Repeat("c", 64)
			case "fingerprint":
				r.Fingerprint = strings.Repeat("c", 64)
			case "domain":
				r.Domain = "evil.test"
			case "expired":
				clock = now.Add(time.Minute)
			case "keyset":
				r.Report = []byte(strings.Replace(string(r.Report), "1750000060", "1750000061", 1))
			case "version":
				r.Report = []byte(strings.Replace(string(r.Report), "aci/1", "aci/2", 1))
			}
			if _, _, err := BindReport(r, clock); err == nil {
				t.Fatal("accepted tampered report")
			}
		})
	}
}

func sessionFixture(t *testing.T, now time.Time) ([]byte, *Proof) {
	evidence := []byte(`{"quote":"synthetic-test-evidence"}`)
	session := map[string]any{"api_version": "aci/1", "verifier_id": "reviewed-test-verifier", "upstream_name": "phala-test",
		"established_at": now.Unix() - 10, "expires_at": now.Unix() + 60, "endpoint": "https://model.test",
		"channel_binding": []any{map[string]any{"type": "tls_spki_sha256", "origin": "https://model.test", "spki_sha256": strings.Repeat("b", 64)}},
		"evidence":        map[string]any{"data": "data:application/json;base64," + base64.StdEncoding.EncodeToString(evidence), "digest": Hash(evidence)}}
	return mustJSON(t, session), &Proof{UpstreamVerifiers: []string{"reviewed-test-verifier"}}
}

func TestSessionRequiresEvidenceAndReviewedChannel(t *testing.T) {
	now := time.Unix(1750000000, 0)
	raw, proof := sessionFixture(t, now)
	if _, err := VerifySession(raw, Hex(raw), proof, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"empty-evidence", "digest", "wrong-content-address", "expired", "unreviewed", "unbound-channel", "empty-json"} {
		t.Run(change, func(t *testing.T) {
			var session map[string]any
			if err := json.Unmarshal(raw, &session); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "empty-evidence":
				session["evidence"] = map[string]any{}
			case "digest":
				session["evidence"].(map[string]any)["digest"] = Hash([]byte("wrong"))
			case "expired":
				session["expires_at"] = now.Unix()
			case "unreviewed":
				session["verifier_id"] = "self-asserted"
			case "unbound-channel":
				session["channel_binding"] = []any{}
			case "empty-json":
				session["evidence"] = map[string]any{"data": "data:application/json;base64,e30=", "digest": Hash([]byte("{}"))}
			}
			changed := mustJSON(t, session)
			id := Hex(changed)
			if change == "wrong-content-address" {
				id = strings.Repeat("f", 64)
			}
			if _, err := VerifySession(changed, id, proof, now); err == nil {
				t.Fatal("accepted unproven session")
			}
		})
	}
}

func TestReceiptRequiresExactExchange(t *testing.T) {
	now := time.Unix(1750000000, 0)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := &Proof{Model: "model", Digest: Hash([]byte("keys")), Keyset: Keyset{NotAfter: now.Unix() + 60, ReceiptKeys: []Key{{ID: "key", Algo: "ed25519", PublicKey: hex.EncodeToString(public)}}}}
	ex := Exchange{ReceiptID: "rcpt-abc", ChatID: "chat-1", RequestHash: Hash([]byte("request")), ResponseHash: Hash([]byte("response")), StartedAt: now, SessionID: strings.Repeat("a", 64), Session: &Session{Upstream: "p", Established: now.Unix() - 10, Expires: now.Unix() + 60}}
	base := map[string]any{"api_version": "aci/1", "receipt_id": ex.ReceiptID, "chat_id": ex.ChatID, "key_id": "key", "workload_keyset_digest": proof.Digest, "model": proof.Model, "method": "POST", "endpoint": "/v1/chat/completions", "served_at": now.Unix(),
		"event_log": []any{map[string]any{"type": "request.received", "body_hash": ex.RequestHash}, map[string]any{"type": "route.selected", "target_route_id": "p:model"}, map[string]any{"type": "upstream.verified", "required": true, "result": "verified", "session_id": ex.SessionID, "model_id": "model"}, map[string]any{"type": "response.returned", "body_hash": ex.ResponseHash}}}
	for _, change := range []string{"good", "model", "keyset", "request", "response", "signature", "unknown-key", "missing-upstream", "duplicate-event", "different-session", "not-required", "not-verified", "route", "replay"} {
		t.Run(change, func(t *testing.T) {
			var value map[string]any
			json.Unmarshal(mustJSON(t, base), &value)
			events := value["event_log"].([]any)
			switch change {
			case "model":
				value["model"] = "other"
			case "keyset":
				value["workload_keyset_digest"] = Hash([]byte("other"))
			case "request":
				events[0].(map[string]any)["body_hash"] = Hash([]byte("other"))
			case "response":
				events[3].(map[string]any)["body_hash"] = Hash([]byte("other"))
			case "unknown-key":
				value["key_id"] = "other"
			case "missing-upstream":
				value["event_log"] = append(events[:2], events[3:]...)
			case "duplicate-event":
				value["event_log"] = append(events, events[0])
			case "different-session":
				events[2].(map[string]any)["session_id"] = strings.Repeat("b", 64)
			case "not-required":
				events[2].(map[string]any)["required"] = false
			case "not-verified":
				events[2].(map[string]any)["result"] = "unverified"
			case "route":
				events[1].(map[string]any)["target_route_id"] = "other:model"
			case "replay":
				value["served_at"] = now.Unix() - 60
			}
			signature := ed25519.Sign(private, mustJSON(t, value))
			if change == "signature" {
				signature[0] ^= 1
			}
			value["signature"] = hex.EncodeToString(signature)
			err := VerifyReceipt(mustJSON(t, value), proof, ex, now)
			if (err == nil) != (change == "good") {
				t.Fatalf("change=%s error=%v", change, err)
			}
		})
	}
}

func encryptionFixture(t *testing.T) *Encryption {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Encryption{Private: key, Server: key.PublicKey(), Model: "demo-model", Nonce: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", Timestamp: 1750000000}
}

func TestOfficialV2AADVectors(t *testing.T) {
	e := encryptionFixture(t)
	request, err := e.AAD("messages.0.content", "", false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}`
	if string(request) != want {
		t.Fatalf("official request vector mismatch: %s", request)
	}
	response, err := e.AAD("choices.0.message.content", "chatcmpl-123", true)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}`
	if string(response) != want {
		t.Fatalf("official response vector mismatch: %s", response)
	}
}

func TestFieldEncryptionBindsEveryContext(t *testing.T) {
	e := encryptionFixture(t)
	aad, _ := e.AAD("messages.0.content", "", false)
	first, err := EncryptField(e.Server, []byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := EncryptField(e.Server, []byte("secret"), aad)
	if first == second {
		t.Fatal("reused ephemeral/nonce")
	}
	plain, err := DecryptField(e.Private, first, aad)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("decrypt: %v", err)
	}
	for _, field := range []string{"model", "nonce", "timestamp", "direction", "path", "response-id"} {
		t.Run(field, func(t *testing.T) {
			changed := *e
			path, id, response := "messages.0.content", "", false
			switch field {
			case "model":
				changed.Model = "other"
			case "nonce":
				changed.Nonce = strings.Repeat("b", 64)
			case "timestamp":
				changed.Timestamp++
			case "direction":
				response = true
			case "path":
				path = "messages.1.content"
			case "response-id":
				response = true
				id = "other"
			}
			wrong, _ := changed.AAD(path, id, response)
			if _, err := DecryptField(e.Private, first, wrong); err == nil {
				t.Fatal("accepted relocated ciphertext")
			}
		})
	}
	for _, raw := range []string{"plaintext", first[:20], first[:len(first)-2], strings.Repeat("0", 120)} {
		if _, err := DecryptField(e.Private, raw, aad); err == nil {
			t.Fatal("accepted corrupt ciphertext")
		}
	}
}

func TestEncryptChatNoPlaintextOrUnsupportedFields(t *testing.T) {
	e := encryptionFixture(t)
	base := map[string]any{"model": e.Model, "stream": true, "messages": []any{map[string]any{"role": "user", "content": "private prompt"}, map[string]any{"role": "user", "content": []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,privateimage"}}}}}}
	wire, _, err := e.EncryptChat(mustJSON(t, base), strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "private") {
		t.Fatal("content leaked")
	}
	for _, field := range []string{"tools", "tool_choice", "response_format", "user", "metadata", "stop", "provider"} {
		t.Run(field, func(t *testing.T) {
			var request map[string]any
			json.Unmarshal(mustJSON(t, base), &request)
			request[field] = "private"
			if _, _, err := e.EncryptChat(mustJSON(t, request), strings.Repeat("a", 64)); err == nil {
				t.Fatal("unprotected field allowed")
			}
		})
	}
}

func TestEncryptedStreamRejectsPlaintextAndTruncation(t *testing.T) {
	e := encryptionFixture(t)
	aad, _ := e.AAD("choices.0.delta.content", "chat-1", true)
	ciphertext, _ := EncryptField(e.Server, []byte("PONG"), aad)
	chunk := mustJSON(t, map[string]any{"id": "chat-1", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": ciphertext}, "finish_reason": nil}}})
	finish := `data: {"id":"chat-1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n"
	valid := "data: " + string(chunk) + "\n\n" + finish + "data: [DONE]\n\n"
	plain, id, err := e.DecryptStream([]byte(valid))
	if err != nil || id != "chat-1" || !strings.Contains(string(plain), "PONG") {
		t.Fatalf("valid encrypted SSE rejected: %v", err)
	}
	for _, bad := range []string{strings.Replace(valid, ciphertext, "PONG", 1), strings.Replace(valid, "data: [DONE]", "", 1), valid + "data: {}\n\n", strings.Replace(valid, finish, "", 1), strings.Replace(valid, `"index":0`, `"index":1`, 1), strings.Replace(valid, `"content":`, `"tool_calls":`, 1)} {
		if _, _, err := e.DecryptStream([]byte(bad)); err == nil {
			t.Fatal("invalid stream accepted")
		}
	}
}

func FuzzACIParsers(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"signature":null}`, `{"api_version":"aci/1","event_log":[null]}`, `{"a":1,"a":2}`, "data: [DONE]\n\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16<<10 {
			return
		}
		now := time.Unix(1750000000, 0)
		proof := &Proof{UpstreamVerifiers: []string{"reviewed"}}
		_, _ = VerifySession(raw, Hex(raw), proof, now)
		_ = VerifyReceipt(raw, proof, Exchange{}, now)
		_, _, _ = BindReport(VerificationRequest{Nonce: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), Report: raw}, now)
	})
}
