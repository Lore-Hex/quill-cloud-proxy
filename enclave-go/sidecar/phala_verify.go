package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/phalaaci"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

// No TOFU: an endpoint's own report cannot approve its release or its KMS.
// An empty policy disables only Phala, not the other sidecar verifiers.
//
//go:embed phala_policy.json
var phalaPolicyJSON []byte

type phalaPolicy struct {
	Domain            string                  `json:"domain"`
	Models            []string                `json:"models"`
	ComposeHash       string                  `json:"compose_hash"`
	OSImageHash       string                  `json:"os_image_hash"`
	Boot              *nearAIBootMeasurements `json:"boot_measurements"`
	KMSRoot           string                  `json:"kms_root_public_key"`
	UpstreamVerifiers []string                `json:"upstream_verifiers"`
	Review            string                  `json:"review"`
}

type phalaEvidence struct {
	Quote   string       `json:"quote"`
	Compose string       `json:"app_compose"`
	Events  string       `json:"event_log"`
	Custody phalaCustody `json:"key_custody"`
}

type phalaVerifier struct {
	policies []phalaPolicy
	now      func() time.Time
	quote    func(string) (*tdxpb.TDQuoteBody, error)
}

func newPhalaVerifier() (*phalaVerifier, error) {
	var policies []phalaPolicy
	if err := phalaaci.Decode(phalaPolicyJSON, &policies); err != nil {
		return nil, err
	}
	for _, p := range policies {
		if (p.Domain != "api.redpill.ai" && p.Domain != "inference.phala.com") || len(p.Models) == 0 || p.Review == "" ||
			!phalaaci.IsHex(p.ComposeHash, 32) || !phalaaci.IsHex(p.OSImageHash, 32) ||
			!phalaaci.IsHex(p.KMSRoot, 33) || len(p.UpstreamVerifiers) == 0 {
			return nil, errors.New("Phala release policy is incomplete")
		}
		if err := p.Boot.validate(); err != nil {
			return nil, err
		}
	}
	return &phalaVerifier{policies: policies, now: time.Now, quote: func(encoded string) (*tdxpb.TDQuoteBody, error) {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("invalid Phala quote encoding")
		}
		return verifyTDXQuote(raw, func(raw []byte) error { return tdxverify.RawTdxQuote(raw, newTDXVerificationOptions()) })
	}}, nil
}

func (v *phalaVerifier) verify(request phalaaci.VerificationRequest) (*phalaaci.Proof, error) {
	now := v.now()
	var policy *phalaPolicy
	var evidence phalaEvidence
	report, keys, err := phalaaci.BindReport(request, now)
	if err != nil {
		return nil, err
	}
	if err := phalaaci.Decode(report.Attestation.Evidence, &evidence); err != nil {
		return nil, err
	}
	for index, p := range v.policies {
		if p.Domain != request.Domain || p.ComposeHash != phalaaci.Hex([]byte(evidence.Compose)) {
			continue
		}
		for _, model := range p.Models {
			if model == request.Model {
				policy = &v.policies[index]
			}
		}
	}
	if policy == nil {
		return nil, errors.New("Phala workload/model has no independently reviewed release policy")
	}
	body, err := v.quote(evidence.Quote)
	if err != nil {
		return nil, errors.New("Phala hardware quote rejected")
	}
	expected, _ := hex.DecodeString(report.Attestation.ReportData)
	expected = append(expected, make([]byte, 32)...)
	if body == nil || !bytes.Equal(body.GetReportData(), expected) {
		return nil, errors.New("Phala quote does not bind challenge/keyset")
	}
	var events []nearAIRuntimeEvent
	if err := phalaaci.Decode([]byte(evidence.Events), &events); err != nil {
		return nil, err
	}
	rtmr3, err := replayNearAIRuntimeEvents(events, policy.ComposeHash, policy.OSImageHash)
	if err != nil {
		return nil, err
	}
	if err := verifyNearAIBoot(body, policy.Boot, rtmr3); err != nil {
		return nil, err
	}
	appID := ""
	for _, event := range events {
		if event.IMR == 3 && event.Event == "app-id" {
			if appID != "" || !phalaaci.IsHex(event.EventPayload, 20) {
				return nil, errors.New("Phala app identity missing or ambiguous")
			}
			appID = event.EventPayload
		}
	}
	if appID == "" {
		return nil, errors.New("Phala measured app identity missing")
	}
	if err := verifyPhalaCustody(evidence.Custody, keys, appID, policy.KMSRoot); err != nil {
		return nil, err
	}
	expires := now.Add(2 * time.Minute)
	if end := time.Unix(keys.NotAfter, 0); end.Before(expires) {
		expires = end
	}
	return &phalaaci.Proof{Policy: phalaaci.PolicyName, Domain: request.Domain, Model: request.Model,
		Fingerprint: request.Fingerprint, VerifiedAt: now, ExpiresAt: expires, Keyset: *keys, Digest: report.Digest,
		UpstreamVerifiers: policy.UpstreamVerifiers}, nil
}

func phalaVerificationHandler(verifier *phalaVerifier) http.HandlerFunc {
	slots := make(chan struct{}, 2)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-ctx.Done():
			http.Error(w, "Phala verification busy", 503)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, phalaaci.MaxArtifactBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid Phala verification request", 400)
			return
		}
		if _, err := phalaaci.Canonical(raw); err != nil {
			http.Error(w, "invalid Phala verification request", 400)
			return
		}
		var request phalaaci.VerificationRequest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid Phala verification request", 400)
			return
		}
		proof, err := verifier.verify(request)
		if err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}
