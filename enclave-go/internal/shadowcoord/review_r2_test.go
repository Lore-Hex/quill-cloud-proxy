package shadowcoord

import (
	"strings"
	"sync"
	"testing"
)

func TestReviewR2UnknownInvalidKeyDoesNotCloseOtherWorkspace(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.ObserveVerdict(strings.Repeat("b", 64), 401, "key_invalid", "")
	if c.reconfirm != 0 || c.bootClosed || len(c.workspaceClosed) != 0 || len(c.keyClosed) != 0 || len(c.infrastructureClosed) != 0 {
		t.Fatal("unresolvable invalid credential changed health before refresh")
	}
	// A clean success and an identical refresh cannot undo the boot-wide closure.
	warm(c, f, r)
	d := c.Predecision(f.Items[0].LookupDigest, req).Decision()
	if !d.Eligible {
		t.Fatalf("unresolvable invalid credential closed unrelated warm workspace; bootClosed=%v decision=%+v", c.bootClosed, d)
	}
}
func TestReviewR2HealthArrivesDuringEvaluation(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	paused := &pausedClock{now: clock.Now(), entered: make(chan struct{}), release: make(chan struct{})}
	c.clock = paused
	result := make(chan Decision, 1)
	go func() { result <- c.Predecision(f.Items[0].LookupDigest, req).Decision() }()
	<-paused.entered
	c.ObserveVerdict(f.Items[0].LookupDigest, 402, "billing_denied", "")
	close(paused.release)
	d := <-result
	if d.Eligible || d.Reason != "snapshot-changed" || c.unresolved != 0 {
		t.Fatal(d, c.unresolved)
	}
	if d = c.Predecision(f.Items[0].LookupDigest, req).Decision(); d.Eligible || d.Reason != "workspace_latched" {
		t.Fatal(d)
	}
}
func TestReviewR2SinglePermit64Contenders(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	var wg sync.WaitGroup
	results := make(chan Decision, 64)
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			x := c.Predecision(f.Items[0].LookupDigest, req)
			results <- x.Decision()
			x.Finish()
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for d := range results {
		if d.Eligible {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("one ordinal admitted %d requests", wins)
	}
}
func TestReviewR2ReleaseRetainsEveryLiability(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	x := c.Predecision(f.Items[0].LookupDigest, req)
	if !x.Decision().Eligible {
		t.Fatal(x.Decision())
	}
	s := c.entries[f.Items[0]]
	before := [4]int64{s.retained, c.workspaceRetained[f.Items[0].WorkspaceID], c.slotRetained, c.fleetRetained}
	x.EndAuthorize("", 0)
	x.Finish()
	x.Finish()
	after := [4]int64{s.retained, c.workspaceRetained[f.Items[0].WorkspaceID], c.slotRetained, c.fleetRetained}
	if before != after || before[0] <= 0 || c.unresolved != 0 || c.memory != 0 {
		t.Fatal(before, after, c.unresolved, c.memory)
	}
}

func TestReviewR2PartialScopeMustPreserveKnownKey(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.ObserveResolvedVerdict(f.Items[0].LookupDigest, 401, "key_invalid", "", Identity{WorkspaceID: f.Items[0].WorkspaceID})
	d := c.Predecision(f.Items[0].LookupDigest, req).Decision()
	if d.Eligible || d.Reason != "key_latched" {
		t.Fatalf("workspace-only denial metadata erased known key identity: %+v", d)
	}
}
func TestReviewR2FaultArrivesDuringEvaluation(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	paused := &pausedClock{now: clock.Now(), entered: make(chan struct{}), release: make(chan struct{})}
	c.clock = paused
	result := make(chan Decision, 1)
	go func() { result <- c.Predecision(f.Items[0].LookupDigest, req).Decision() }()
	<-paused.entered
	c.Fault()
	close(paused.release)
	d := <-result
	if d.Eligible || d.Reason != "snapshot-changed" {
		t.Fatal("callback fault lost during evaluation", d)
	}
}
