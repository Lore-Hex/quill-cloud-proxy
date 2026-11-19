package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"
)

// Only the signed device evidence goes to NVIDIA, never the Fortanix token,
// quote, provider debug data, or inference input. No fallback or POST retries.
func fortanixGroup(ctx context.Context, v *nrasVerifier, kind, arch, nonce string, devices []fortanixDevice) ([]map[string]any, error) {
	if kind != "gpu" && kind != "switch" {
		return nil, errors.New("unexpected NVIDIA verifier")
	}
	type item struct {
		Evidence    string `json:"evidence"`
		Certificate string `json:"certificate"`
	}
	items := make([]item, len(devices))
	for i, d := range devices {
		items[i] = item{d.Evidence, d.Certificate}
	}
	payload, err := json.Marshal(map[string]any{"evidence_list": items, "arch": arch, "nonce": nonce, "claims_version": "3.0"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chutesNRASIssuer+"/v4/attest/"+kind, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVIDIA %s verifier HTTP %d", kind, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, chutesMaxNRASBytes+1))
	if err != nil || len(raw) > chutesMaxNRASBytes {
		return nil, errors.New("invalid NVIDIA response size")
	}
	return fortanixClaims(v, raw, kind, nonce, len(devices))
}

func fortanixClaims(v *nrasVerifier, raw []byte, kind, nonce string, count int) ([]map[string]any, error) {
	var env []json.RawMessage
	var overall []string
	var detached map[string]string
	if json.Unmarshal(raw, &env) != nil || len(env) != 2 || json.Unmarshal(env[0], &overall) != nil || len(overall) != 2 || overall[0] != "JWT" ||
		json.Unmarshal(env[1], &detached) != nil || len(detached) != count {
		return nil, errors.New("invalid NVIDIA EAT bundle")
	}
	c, err := v.verifyJWT(overall[1], true)
	if err != nil {
		return nil, err
	}
	if !fortanixFresh(c, v.now()) {
		return nil, errors.New("NVIDIA overall token freshness check failed")
	}
	if c["iss"] != chutesNRASIssuer || c["sub"] != "NVIDIA-PLATFORM-ATTESTATION" || c["eat_nonce"] != nonce || c["x-nvidia-ver"] != "3.0" {
		return nil, errors.New("NVIDIA overall token issuer, subject, nonce or claims version mismatch")
	}
	if c["x-nvidia-overall-att-result"] != true {
		return nil, errors.New("NVIDIA did not attest the device group")
	}
	mods, ok := c["submods"].(map[string]any)
	if !ok || len(mods) != count {
		return nil, errors.New("NVIDIA overall token lacks the expected detached devices")
	}
	out := make([]map[string]any, 0, count)
	seen := map[string]bool{}
	for name, token := range detached {
		hash := sha256.Sum256([]byte(token))
		wrapper, _ := mods[name].([]any)
		if len(wrapper) != 2 || wrapper[0] != "DIGEST" {
			return nil, errors.New("missing signed device digest")
		}
		pair, _ := wrapper[1].([]any)
		if len(pair) != 2 || pair[0] != "SHA-256" || pair[1] != hex.EncodeToString(hash[:]) {
			return nil, errors.New("detached NVIDIA device digest mismatch")
		}
		device, err := v.verifyJWT(token, true)
		if err != nil {
			return nil, err
		}
		id, _ := device["ueid"].(string)
		if !fortanixFresh(device, v.now()) || id == "" || seen[id] || device["iss"] != chutesNRASIssuer || device["eat_nonce"] != nonce {
			return nil, errors.New("NVIDIA device freshness, identity or nonce mismatch")
		}
		seen[id] = true
		if err := fortanixDevicePolicy(device, kind); err != nil {
			return nil, err
		}
		out = append(out, device)
	}
	return out, nil
}

func fortanixFresh(c map[string]any, now time.Time) bool {
	iat, ok := numericDate(c["iat"])
	exp, hasExpiry := numericDate(c["exp"])
	if v, exists := c["nbf"]; exists {
		start, valid := numericDate(v)
		if !valid || start.After(now) {
			return false
		}
	}
	// The first group must still be valid when the second group finishes.
	return ok && !iat.Before(now.Add(-5*time.Minute)) && !iat.After(now.Add(2*time.Minute)) && hasExpiry && exp.After(now.Add(fortanixAppraisalWindow))
}

func fortanixDevicePolicy(c map[string]any, kind string) error {
	if c["measres"] != "success" || c["dbgstat"] != "disabled" || c["secboot"] != true || c["x-nvidia-attestation-warning"] != nil {
		return errors.New("NVIDIA device boot, debug, warning or measurement policy failed")
	}
	checks := []string{"arch-check", "attestation-report-parsed", "attestation-report-nonce-match", "attestation-report-signature-verified", "attestation-report-cert-chain-fwid-match"}
	chains := []string{"attestation-report-cert-chain"}
	var rims []string
	switch kind {
	case "gpu":
		// Both exact encodings identify the Hopper die, not an H200 SKU.
		// Firmware and certificate checks below apply to either spelling.
		if c["hwmodel"] != "GH100 A01 GSP BROM" && c["hwmodel"] != "GH100" {
			return fortanixModelMismatch("GPU", c["hwmodel"])
		}
		checks = append(checks, "vbios-index-no-conflict")
		rims = []string{"vbios-rim", "driver-rim"}
	case "switch":
		if c["hwmodel"] != "LS_10 A01 FSP BROM" {
			return fortanixModelMismatch("NVSwitch", c["hwmodel"])
		}
		rims = []string{"bios-rim"}
	default:
		return errors.New("unexpected device kind")
	}
	for _, rim := range rims {
		chains = append(chains, rim+"-cert-chain")
		for _, s := range []string{"-fetched", "-schema-validated", "-signature-verified", "-version-match", "-measurements-available"} {
			checks = append(checks, rim+s)
		}
	}
	prefix := "x-nvidia-" + kind + "-"
	for _, key := range checks {
		if c[prefix+key] != true {
			return fmt.Errorf("missing or failed NVIDIA claim: %s%s", prefix, key)
		}
	}
	for _, key := range chains {
		m, _ := c[prefix+key].(map[string]any)
		if m["x-nvidia-cert-status"] != "valid" || m["x-nvidia-cert-ocsp-status"] != "good" || m["x-nvidia-cert-revocation-reason"] != nil {
			return fmt.Errorf("NVIDIA %s%s certificate chain not valid and good", prefix, key)
		}
	}
	return nil
}

// Print known, public model labels only. This is a diagnostic vocabulary,
// not an acceptance list. Never print arbitrary device-supplied identifiers.
func fortanixModelMismatch(group string, claim any) error {
	label, ok := claim.(string)
	if !ok || label == "" {
		return fmt.Errorf("%s has a missing or invalid signed hwmodel", group)
	}
	switch label {
	case "GH100", "LS_10", "GH100 A01 GSP BROM", "LS_10 A01 FSP BROM":
		return fmt.Errorf("%s signed hwmodel %q differs from the qualification policy", group, label)
	default:
		return fmt.Errorf("%s signed hwmodel differs from the qualification policy (unrecognized value withheld)", group)
	}
}

func fortanixPDI(v any) (string, bool) {
	s, ok := v.(string)
	b, err := hex.DecodeString(s)
	return strings.ToUpper(s), ok && err == nil && len(b) == 8
}

func fortanixLinks(v any, count int, allowDisabled bool) (map[string]bool, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, errors.New("missing NVIDIA fabric link evidence")
	}
	seen := map[string]bool{}
	for _, item := range items {
		id, ok := fortanixPDI(item)
		if !ok {
			return nil, errors.New("invalid NVIDIA fabric identifier")
		}
		if id == "0000000000000000" {
			if allowDisabled {
				continue
			}
			return nil, errors.New("inactive GPU link")
		}
		seen[id] = true
	}
	if len(seen) != count {
		return nil, errors.New("incomplete NVIDIA fabric link set")
	}
	return seen, nil
}

// NVIDIA's HGX PPCIe topology policy: every GPU sees the same four actual
// switches, and every switch sees the same eight GPUs.
func fortanixFabric(gpus, switches []map[string]any) error {
	if len(gpus) != 8 || len(switches) != 4 {
		return errors.New("unexpected PPCIe group size")
	}
	sids := map[string]bool{}
	var gids map[string]bool
	for _, sw := range switches {
		id, ok := fortanixPDI(sw["x-nvidia-switch-pdi"])
		if !ok || id == "0000000000000000" || sids[id] {
			return errors.New("invalid or duplicate switch identity")
		}
		sids[id] = true
		g, err := fortanixLinks(sw["x-nvidia-switch-gpu-pdis"], 8, false)
		if err != nil {
			return err
		}
		if gids != nil && !maps.Equal(gids, g) {
			return errors.New("switches disagree on GPU topology")
		}
		gids = g
	}
	for _, gpu := range gpus {
		s, err := fortanixLinks(gpu["x-nvidia-gpu-switch-pdis"], 4, true)
		if err != nil {
			return err
		}
		if !maps.Equal(s, sids) {
			return errors.New("GPU and switch topology disagree")
		}
	}
	return nil
}
