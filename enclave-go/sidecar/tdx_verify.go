package main

import (
	"errors"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

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
