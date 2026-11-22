package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

const fortanixModel = "GLM-5.3-Flash"

// Candidate reference only, not a production admission list. Source:
// fortanix/armet-ctf@5ba767a9553173bb4fc3977a979f8e7cbc0e36b8.
var fortanixCandidateRegisters = [...]string{
	"c78e2b8b2f66207f3807d8d999f51e04f5eab8f7aa02614a86ddd81b61f4e79c5d7616664fcb190b8eaae2e26d60b12a",
	"e5cdf26849fab476158bfc0125d8b43f53776fdab22329fa543394fa35dba8f11a4009633e4e19e43dcba5e73a365225",
	"b5b6a4094ad7f0723d5227df263144bbd36c2c0859142621cdfce286c06496b8a615aa513ece512bfeb8dd0ac7125419",
	"b767cba3ab019c2c8a9027f87bd81074dcad56e8332d3b5df71edc37fced2915574cf79389aa86922a6e41aa512d26e3",
	"fffc07f5a1762199c0b9c03822dce398ec5737452fdf079636fa7898829d9f9b09bf7666eddf4c73b04171b3dc199d8d",
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
}

type fortanixReport struct {
	Version int    `json:"version"`
	Model   string `json:"model_id"`
	Nonce   string `json:"nonce"`
	SPKI    string `json:"tls_spki_sha256"`
	Quote   string `json:"quote"`
	Payload string `json:"nvidia_payload"`
}

type fortanixDevice struct {
	Nonce       string `json:"nonce"`
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
}

type fortanixDevices struct {
	Nonce         string           `json:"nonce"`
	Arch          string           `json:"arch"`
	SwitchArch    []string         `json:"switch_arch"`
	GPUs          []fortanixDevice `json:"evidence_list"`
	Switches      []fortanixDevice `json:"switch_evidence_list"`
	SwitchPresent bool             `json:"switch_evidence_present"`
}

// gw_digest in /opt/cvn/attest_server.py in image b5269d74. REPORTDATA is
// the 64 ASCII hex characters, not a binary digest followed by zero padding.
func fortanixReportData(nonce, spki [32]byte, payload string) []byte {
	h := sha256.New()
	h.Write([]byte("private-ai-gateway/armet-ai/v2\x00"))
	h.Write(nonce[:])
	h.Write(spki[:])
	p := sha256.Sum256([]byte(payload))
	h.Write(p[:])
	h.Write([]byte(fortanixModel))
	return []byte(hex.EncodeToString(h.Sum(nil)))
}

func fortanixBoundDevices(raw []byte, nonce, spki [32]byte) (*fortanixDevices, error) {
	var r fortanixReport
	if len(raw) > 1<<20 || !utf8.Valid(raw) || json.Unmarshal(raw, &r) != nil || r.Version != 2 || r.Model != fortanixModel ||
		r.Nonce != hex.EncodeToString(nonce[:]) || r.SPKI != hex.EncodeToString(spki[:]) {
		return nil, errors.New("Fortanix model, nonce, protocol or TLS identity mismatch")
	}
	quote, err := hex.DecodeString(r.Quote)
	if err != nil {
		return nil, errors.New("invalid Fortanix TDX quote encoding")
	}
	body, err := verifyTDXQuote(quote, func(b []byte) error { return tdxverify.RawTdxQuote(b, newTDXVerificationOptions()) })
	if err != nil {
		return nil, err
	}
	return fortanixVerifiedDevices(body, r, nonce, spki)
}

func fortanixVerifiedDevices(body *tdxpb.TDQuoteBody, r fortanixReport, nonce, spki [32]byte) (*fortanixDevices, error) {
	regs := [][]byte{body.GetMrTd(), body.GetMrConfigId()}
	regs = append(regs, body.GetRtmrs()...)
	if len(regs) != len(fortanixCandidateRegisters) {
		return nil, errors.New("Fortanix TDX register count mismatch")
	}
	for i, reg := range regs {
		if hex.EncodeToString(reg) != fortanixCandidateRegisters[i] {
			return nil, errors.New("Fortanix workload differs from candidate reference")
		}
	}
	if !bytes.Equal(body.GetReportData(), fortanixReportData(nonce, spki, r.Payload)) {
		return nil, errors.New("Fortanix signed channel binding mismatch")
	}
	var devices fortanixDevices
	if json.Unmarshal([]byte(r.Payload), &devices) != nil || devices.Nonce != r.Nonce || devices.Arch != "HOPPER" || !devices.SwitchPresent ||
		len(devices.SwitchArch) != 1 || devices.SwitchArch[0] != "LS10" || len(devices.GPUs) != 8 || len(devices.Switches) != 4 {
		return nil, errors.New("Fortanix PPCIe inventory or challenge mismatch")
	}
	seen := map[string]bool{}
	for _, group := range []struct {
		arch    string
		devices []fortanixDevice
	}{{"HOPPER", devices.GPUs}, {"LS10", devices.Switches}} {
		for _, entry := range group.devices {
			if entry.Nonce != r.Nonce || entry.Arch != group.arch || entry.Certificate == "" || entry.Evidence == "" || seen[entry.Certificate] {
				return nil, errors.New("Fortanix PPCIe device evidence missing, repeated or inconsistent")
			}
			seen[entry.Certificate] = true
		}
	}
	return &devices, nil
}
