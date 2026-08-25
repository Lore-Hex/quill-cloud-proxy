package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

const (
	tdxCollateralTimeout  = 20 * time.Second
	tdxCollateralMaxBytes = 16 << 20
)

var intelCollateralHosts = map[string]struct{}{
	"api.trustedservices.intel.com":          {},
	"certificates.trustedservices.intel.com": {},
}

type intelCollateralGetter struct {
	client *http.Client
}

func newTDXVerificationOptions() *tdxverify.Options {
	opts := tdxverify.DefaultOptions()
	opts.GetCollateral = true
	opts.CheckRevocations = true
	opts.Getter = &intelCollateralGetter{client: &http.Client{
		Timeout: tdxCollateralTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("Intel collateral redirects are forbidden")
		},
	}}
	return opts
}

func validateIntelCollateralURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" ||
		parsed.Fragment != "" {
		return errors.New("Intel collateral URL is not a pinned HTTPS authority")
	}
	host := strings.ToLower(parsed.Hostname())
	if _, ok := intelCollateralHosts[host]; !ok || parsed.Hostname() != host {
		return errors.New("Intel collateral URL has an untrusted authority")
	}
	return nil
}

func (g *intelCollateralGetter) Get(raw string) (map[string][]string, []byte, error) {
	if err := validateIntelCollateralURL(raw); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json, application/pkix-crl, application/octet-stream")
	req.Header.Set("User-Agent", "TrustedRouter-TDX-Verifier/1.0")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, nil, fmt.Errorf("Intel collateral returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, tdxCollateralMaxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > tdxCollateralMaxBytes {
		return nil, nil, errors.New("Intel collateral exceeded size limit")
	}
	return resp.Header.Clone(), body, nil
}

// verifyTDXQuote verifies Intel collateral, revocation, and current TCB through
// the caller-provided verifier, then returns a parsed, production-mode QuoteV4.
func verifyTDXQuote(raw []byte, verify func([]byte) error) (*tdxpb.TDQuoteBody, error) {
	if len(raw) == 0 {
		return nil, errors.New("Intel TDX quote is empty")
	}
	if err := verify(raw); err != nil {
		return nil, fmt.Errorf("Intel TDX verification failed: %w", err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("parse verified Intel TDX quote: %w", err)
	}
	quote, ok := parsed.(*tdxpb.QuoteV4)
	if !ok || quote.GetTdQuoteBody() == nil {
		return nil, errors.New("verified Intel quote is not TDX QuoteV4")
	}
	body := quote.GetTdQuoteBody()
	if len(body.GetTdAttributes()) != 8 || body.GetTdAttributes()[0]&1 != 0 {
		return nil, errors.New("Intel TDX workload has debug mode enabled or invalid attributes")
	}
	return body, nil
}
