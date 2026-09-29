package main

import "testing"

// Sol's reproduction: an abandoned provider from the bounded-drain test must be
// joined before a later test swaps os.Stderr, or -race reports provider logging.
func TestBoundedDrainLeavesNoProviderForTheNextTest(t *testing.T) {
	t.Run("drain", TestFusionCallDrainIsBoundedWhenAProviderIgnoresCancel)
	_ = captureStderr(t, func() {})
}
