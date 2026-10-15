package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

type auditIntelGetter struct {
	base   trust.HTTPSGetter
	t      *testing.T
	module string
	svn    byte
}

func (g *auditIntelGetter) Get(url string) (map[string][]string, []byte, error) {
	headers, body, err := g.base.Get(url)
	if err == nil && strings.Contains(url, "/tcb?") {
		var document struct {
			TCBInfo struct {
				FMSPC      string `json:"fmspc"`
				IssueDate  string `json:"issueDate"`
				NextUpdate string `json:"nextUpdate"`
				Modules    []struct {
					ID     string `json:"id"`
					Levels []struct {
						TCB struct {
							SVN int `json:"isvsvn"`
						} `json:"tcb"`
						Status string `json:"tcbStatus"`
					} `json:"tcbLevels"`
				} `json:"tdxModuleIdentities"`
			} `json:"tcbInfo"`
		}
		if json.Unmarshal(body, &document) == nil {
			g.t.Logf("Intel PCS collateral fmspc=%s issued=%s expires=%s module=%s quoted_svn=%d", document.TCBInfo.FMSPC, document.TCBInfo.IssueDate, document.TCBInfo.NextUpdate, g.module, g.svn)
			for _, module := range document.TCBInfo.Modules {
				if module.ID == g.module {
					for _, level := range module.Levels {
						g.t.Logf("Intel module level min_svn=%d status=%s", level.TCB.SVN, level.Status)
					}
				}
			}
		}
	}
	return headers, body, err
}

// Quote-only diagnosis: no inference and no evidence submitted to NVIDIA.
// Parsed SVN values are diagnostic, never used to accept an unverified quote.
func TestLiveNearAIIntelEvidence(t *testing.T) {
	dir := os.Getenv("TR_LIVE_NEAR_AI_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("set TR_LIVE_NEAR_AI_EVIDENCE_DIR")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("missing evidence: %v", err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var request nearAIVerificationRequest
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			var report nearAIReport
			if err := json.Unmarshal(request.Evidence, &report); err != nil {
				t.Fatal(err)
			}
			quote, err := hex.DecodeString(report.IntelQuote)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := abi.QuoteToProto(quote)
			if err != nil {
				t.Fatal(err)
			}
			v4, ok := parsed.(*tdxpb.QuoteV4)
			if !ok || v4.GetTdQuoteBody() == nil {
				t.Fatal("expected V4 quote")
			}
			svn := v4.GetTdQuoteBody().GetTeeTcbSvn()
			if len(svn) < 2 {
				t.Fatal("invalid TEE TCB SVN")
			}
			opts := newTDXVerificationOptions()
			opts.Getter = &auditIntelGetter{base: opts.Getter, t: t, module: fmt.Sprintf("TDX_%02x", svn[1]), svn: svn[0]}
			if err := tdxverify.RawTdxQuote(quote, opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}
