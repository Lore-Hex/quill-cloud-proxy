package main

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// A provider goroutine that keeps working after the collector has its answer
// (for example logging its attempt) must finish before the call that owns it
// returns. CI caught it logging to a stderr a later test had swapped
// (TestHostedDecidePrefersTheVendorAndBillsInputOnly, a DATA RACE on main).
func TestFusionCallWaitsForItsProviderGoroutine(t *testing.T) {
	var finished atomic.Bool
	provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
		if err := writeAnthropicTextTestStream(out, req.Model, "answer"); err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond) // still working after message_stop
		finished.Store(true)
		return nil
	})
	gateway, _ := newFusionBudgetGateway(t)
	req := &types.OpenAIChatRequest{Model: "model/test", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	if _, err := runFusionCall(t.Context(), provider, req, gateway, nil, "bearer", "fusion.panel", "drain", "drain", nil, false); err != nil {
		t.Fatal(err)
	}
	if !finished.Load() {
		t.Fatal("the fusion call returned while its provider goroutine was still running")
	}
}

func TestFusionCallDrainIsBoundedWhenAProviderIgnoresCancel(t *testing.T) {
	old := fusionProviderDrainTimeout
	fusionProviderDrainTimeout = 30 * time.Millisecond
	t.Cleanup(func() { fusionProviderDrainTimeout = old })
	release := make(chan struct{})
	t.Cleanup(func() {
		// Join the whole abandoned invocation, including its final logging, so it
		// cannot race a later test that swaps os.Stderr.
		close(release)
		deadline := time.Now().Add(5 * time.Second)
		for providersInFlight.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if n := providersInFlight.Load(); n != 0 {
			t.Errorf("%d provider goroutines still running after release", n)
		}
	})
	provider := advisorTimeoutLLM(func(ctx context.Context, req *types.OpenAIChatRequest, out io.Writer) error {
		if err := writeAnthropicTextTestStream(out, req.Model, "answer"); err != nil {
			return err
		}
		<-release // ignores ctx entirely
		return nil
	})
	gateway, _ := newFusionBudgetGateway(t)
	req := &types.OpenAIChatRequest{Model: "model/test", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
	started := time.Now()
	if _, err := runFusionCall(t.Context(), provider, req, gateway, nil, "bearer", "fusion.panel", "drain2", "drain2", nil, false); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("drain was not bounded: %s", elapsed)
	}
}
