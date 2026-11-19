package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"testing"
)

func TestFortanixPublishedBinding(t *testing.T) {
	var n, s [32]byte
	for i := range n {
		n[i] = byte(i)
		s[i] = byte(i + 32)
	}
	if string(fortanixReportData(n, s, "{}")) != "841a47fc047e13daa27209c8cc0516e23775e5ff6dd7bd9c7d7c3fba832e6124" {
		t.Fatal("binding byte representation changed")
	}
}

func TestFortanixVerifiedBody(t *testing.T) {
	n := sha256.Sum256([]byte("test challenge"))
	s := sha256.Sum256([]byte("test key"))
	h := hex.EncodeToString(n[:])
	for _, scenario := range []string{"valid", "other socket", "other nonce", "wire whitespace", "wrong register", "missing register", "bad leaf nonce", "repeated device", "missing switch", "wrong architecture", "bad JSON"} {
		t.Run(scenario, func(t *testing.T) {
			ds := fortanixDevices{Nonce: h, Arch: "HOPPER", SwitchArch: []string{"LS10"}, SwitchPresent: true}
			for i := 0; i < 12; i++ {
				d := fortanixDevice{Nonce: h, Arch: "HOPPER", Certificate: fmt.Sprintf("test cert %d", i), Evidence: "test evidence"}
				if i < 8 {
					ds.GPUs = append(ds.GPUs, d)
				} else {
					d.Arch = "LS10"
					ds.Switches = append(ds.Switches, d)
				}
			}
			switch scenario {
			case "bad leaf nonce":
				ds.GPUs[3].Nonce = "other"
			case "repeated device":
				ds.GPUs[1] = ds.GPUs[0]
			case "missing switch":
				ds.Switches = ds.Switches[:3]
			case "wrong architecture":
				ds.Switches[1].Arch = "HOPPER"
			}
			p, err := json.Marshal(ds)
			if err != nil {
				t.Fatal(err)
			}
			r := fortanixReport{Nonce: h, Payload: string(p)}
			if scenario == "bad JSON" {
				r.Payload = "invalid"
			}
			regs := make([][]byte, len(fortanixCandidateRegisters))
			for i, v := range fortanixCandidateRegisters {
				regs[i], err = hex.DecodeString(v)
				if err != nil {
					t.Fatal(err)
				}
			}
			b := &tdxpb.TDQuoteBody{MrTd: regs[0], MrConfigId: regs[1], Rtmrs: regs[2:], ReportData: fortanixReportData(n, s, r.Payload)}
			n1, s1 := n, s
			switch scenario {
			case "other nonce":
				n1[0] ^= 1
			case "other socket":
				s1[0] ^= 1
			case "wire whitespace":
				r.Payload += " "
			case "wrong register":
				b.MrConfigId[3] ^= 1
			case "missing register":
				b.Rtmrs = b.Rtmrs[:3]
			}
			result, err := fortanixVerifiedDevices(b, r, n1, s1)
			if (err == nil) != (scenario == "valid") || (result != nil) != (err == nil) {
				t.Fatalf("unexpected verdict: %v", err)
			}
		})
	}
}
