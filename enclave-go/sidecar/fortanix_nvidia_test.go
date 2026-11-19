package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFortanixModelMismatchDoesNotRepinOrDisclose(t *testing.T) {
	for _, tc := range []struct {
		model      any
		diagnostic string
	}{
		{"GH100", `signed hwmodel "GH100"`}, {"private-fixture-id", "value withheld"},
		{nil, "missing or invalid"}, {map[string]string{"ueid": "private-fixture-id"}, "missing or invalid"},
	} {
		claims := testFortanixClaims("gpu", 0, "test nonce", time.Now())
		claims["hwmodel"] = tc.model
		err := fortanixDevicePolicy(claims, "gpu")
		if err == nil || !strings.Contains(err.Error(), tc.diagnostic) || strings.Contains(err.Error(), "private-fixture-id") {
			t.Fatal("unexpected model accepted, mislabeled or disclosed")
		}
	}
}

func testFabricIDs(start, count int) []any {
	out := make([]any, count)
	for i := range out {
		out[i] = fmt.Sprintf("%016x", i+start)
	}
	return out
}

func testFortanixClaims(kind string, i int, nonce string, now time.Time) map[string]any {
	c := map[string]any{"iss": chutesNRASIssuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "eat_nonce": nonce, "ueid": fmt.Sprintf("fixture-%s-%d", kind, i), "dbgstat": "disabled", "secboot": true, "measres": "success"}
	prefix := "x-nvidia-" + kind + "-"
	for _, k := range []string{"arch-check", "attestation-report-parsed", "attestation-report-nonce-match", "attestation-report-signature-verified", "attestation-report-cert-chain-fwid-match"} {
		c[prefix+k] = true
	}
	rims := []string{"vbios-rim", "driver-rim"}
	if kind == "gpu" {
		c["hwmodel"] = "GH100 A01 GSP BROM"
		c[prefix+"vbios-index-no-conflict"] = true
		c[prefix+"switch-pdis"] = testFabricIDs(11, 4)
	} else {
		rims = []string{"bios-rim"}
		c["hwmodel"] = "LS_10 A01 FSP BROM"
		c[prefix+"pdi"] = testFabricIDs(11, 4)[i]
		c[prefix+"gpu-pdis"] = testFabricIDs(31, 8)
	}
	chain := map[string]any{"x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "good"}
	c[prefix+"attestation-report-cert-chain"] = chain
	for _, r := range rims {
		c[prefix+r+"-cert-chain"] = chain
		for _, k := range []string{"fetched", "schema-validated", "signature-verified", "version-match", "measurements-available"} {
			c[prefix+r+"-"+k] = true
		}
	}
	return c
}

func TestFortanixNVIDIAAppraisal(t *testing.T) {
	now := time.Now().UTC()
	nonce := "test-nonce"
	server := newNRASTestServer(t, now, nonce, true)
	defer server.server.Close()
	verifier := server.verifier()
	var groups [][]map[string]any
	for _, kind := range []string{"gpu", "switch"} {
		count := 8
		if kind == "switch" {
			count = 4
		}
		for _, scenario := range []string{"valid", "wrong device nonce", "revoked", "duplicate identity", "expired", "expires during appraisal", "not yet valid", "stale", "missing issue time", "detached mismatch", "declined", "wrong hardware", "warning", "bad signature"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				mods := map[string]any{}
				detached := map[string]string{}
				for i := 0; i < count; i++ {
					c := testFortanixClaims(kind, i, nonce, now)
					if i == 1 {
						switch scenario {
						case "wrong device nonce":
							c["eat_nonce"] = "other"
						case "revoked":
							c["x-nvidia-"+kind+"-attestation-report-cert-chain"].(map[string]any)["x-nvidia-cert-ocsp-status"] = "revoked"
						case "duplicate identity":
							c["ueid"] = fmt.Sprintf("fixture-%s-0", kind)
						case "expired":
							c["exp"] = now.Add(-time.Minute).Unix()
						case "expires during appraisal":
							c["exp"] = now.Add(30 * time.Second).Unix()
						case "not yet valid":
							c["nbf"] = now.Add(time.Minute).Unix()
						case "stale":
							c["iat"] = now.Add(-time.Hour).Unix()
						case "missing issue time":
							delete(c, "iat")
						case "wrong hardware":
							c["hwmodel"] = "unapproved"
						case "warning":
							c["x-nvidia-attestation-warning"] = "refused"
						}
					}
					token := signTestES384JWT(t, server.key, "nras-test", c)
					id := fmt.Sprintf("%s-%d", kind, i)
					h := sha256.Sum256([]byte(token))
					mods[id] = []any{"DIGEST", []any{"SHA-256", hex.EncodeToString(h[:])}}
					detached[id] = token
					if i == 1 && scenario == "detached mismatch" {
						detached[id] += "x"
					}
				}
				overall := map[string]any{"iss": chutesNRASIssuer, "sub": "NVIDIA-PLATFORM-ATTESTATION", "eat_nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "x-nvidia-ver": "3.0", "x-nvidia-overall-att-result": scenario != "declined", "submods": mods}
				signed := signTestES384JWT(t, server.key, "nras-test", overall)
				if scenario == "bad signature" {
					signed = signed[:len(signed)-5]
				}
				raw, err := json.Marshal([]any{[]string{"JWT", signed}, detached})
				if err != nil {
					t.Fatal(err)
				}
				group, err := fortanixClaims(verifier, raw, kind, nonce, count)
				if (err == nil) != (scenario == "valid") {
					t.Fatalf("unexpected signed verdict: %v", err)
				}
				if err == nil {
					groups = append(groups, group)
				}
			})
		}
	}
	if len(groups) != 2 {
		t.Fatal("missing accepted test groups")
	}
	g, s := groups[0], groups[1]
	if err := fortanixFabric(g, s); err != nil {
		t.Fatal(err)
	}
	g[0]["x-nvidia-gpu-switch-pdis"] = testFabricIDs(51, 4)
	if fortanixFabric(g, s) == nil {
		t.Fatal("accepted a disconnected GPU")
	}
	g[0]["x-nvidia-gpu-switch-pdis"] = testFabricIDs(11, 4)
	s[1]["x-nvidia-switch-gpu-pdis"] = testFabricIDs(41, 8)
	if fortanixFabric(g, s) == nil {
		t.Fatal("accepted inconsistent switch topology")
	}
}
