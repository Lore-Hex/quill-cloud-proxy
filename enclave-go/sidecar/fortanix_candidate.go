package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const fortanixAppraisalWindow = 90 * time.Second

// Candidate qualification, intentionally not registered as a production
// verifier. A CPU-only pass is never a successful full appraisal.
func appraiseFortanixCandidate(ctx context.Context, raw []byte, nonce, spki [sha256.Size]byte) error {
	ctx, cancel := context.WithTimeout(ctx, fortanixAppraisalWindow)
	defer cancel()
	devices, err := fortanixBoundDevices(raw, nonce, spki)
	if err != nil {
		return err
	}
	v := newNRASVerifier()
	v.client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("NVIDIA redirects forbidden") }
	n := hex.EncodeToString(nonce[:])
	g, err := fortanixGroup(ctx, v, "gpu", "HOPPER", n, devices.GPUs)
	if err != nil {
		return err
	}
	s, err := fortanixGroup(ctx, v, "switch", "LS10", n, devices.Switches)
	if err != nil {
		return err
	}
	if err := fortanixFabric(g, s); err != nil {
		return err
	}
	return ctx.Err()
}
