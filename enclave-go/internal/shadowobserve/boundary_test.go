package shadowobserve

import (
	"runtime"
	"testing"
	"time"
)

func TestBoundaryOnlyRecoversCallbackPanics(t *testing.T) {
	var b Boundary
	if !Protect(&b, func() {}) || b.Failures() != 0 {
		t.Fatal("successful callback")
	}
	if Protect(&b, func() { panic("callback") }) || b.Failures() != 1 {
		t.Fatal("unaccounted panic")
	}
	func() { defer b.Recover(); panic("worker") }()
	if b.Failures() != 2 {
		t.Fatal("worker loss")
	}
	// Goexit must still exit the goroutine, not return from Protect.
	done := make(chan struct{})
	returned := make(chan struct{}, 1)
	go func() { defer close(done); Protect(&b, runtime.Goexit); returned <- struct{}{} }()
	<-done
	select {
	case <-returned:
		t.Fatal("runtime exit swallowed")
	default:
	}
	if b.Failures() != 2 {
		t.Fatal("runtime exit counted as callback panic")
	}
}

type faultHost struct {
	Boundary
	panicAt  string
	releases int
}

func (h *faultHost) Mono() time.Duration {
	if h.panicAt == "clock" {
		panic("clock")
	}
	return 0
}
func (h *faultHost) Emit(Record) {
	if h.panicAt == "emit" {
		panic("emit")
	}
}
func (h *faultHost) Release(Identity, string) {
	h.releases++
	if h.panicAt == "release" {
		panic("release")
	}
}
func TestExecutionCallbackBoundaries(t *testing.T) {
	for _, at := range []string{"clock", "emit", "release"} {
		t.Run(at, func(t *testing.T) {
			h := &faultHost{}
			x := NewExecution(h, "x", Decision{}, Identity{}, Route{})
			h.panicAt = at
			if at == "clock" {
				x.StartAuthorize("", "")
				x.Now()
				x.ObserveAttempt(0, 200, nil)
			} else {
				x.Finish()
			}
			if h.Failures() == 0 {
				t.Fatal("host not failed closed")
			}
		})
	}
}
func TestByteValidators(t *testing.T) {
	for _, s := range []string{"a", "Z", "09_.:-"} {
		if !validIdentifier(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "a b", "é", "/"} {
		if validIdentifier(s) {
			t.Fatal(s)
		}
	}
	if validDigest("g"+string(make([]byte, 63))) || validDigest("abc") {
		t.Fatal("digest")
	}
}

func TestEndAuthorizeClockFaultUnlocksAndReleases(t *testing.T) {
	h := &faultHost{}
	x := NewExecution(h, "x", Decision{}, Identity{}, Route{})
	x.StartAuthorize("", "")
	h.panicAt = "clock"
	x.EndAuthorize("", 200)
	done := make(chan struct{})
	go func() { x.Finish(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback fault leaked execution mutex")
	}
	if h.Failures() != 1 || h.releases != 2 {
		t.Fatal(h.Failures(), h.releases)
	}
}
