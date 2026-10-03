package shadowobserve

import "sync/atomic"

// Boundary contains only shadow code. It does not wrap ordinary I/O or change
// returned errors. Goexit and runtime exits are not panics and are not recovered.
// Panic values are deliberately discarded: they may contain request content.
type Boundary struct{ failures atomic.Uint64 }

func (b *Boundary) Fault()           { b.failures.Add(1) }
func (b *Boundary) Failures() uint64 { return b.failures.Load() }
func (b *Boundary) Recover() {
	if recover() != nil {
		b.Fault()
	}
}
func Protect(owner interface{ Fault() }, callback func()) (ok bool) {
	defer func() {
		if recover() != nil {
			owner.Fault()
		}
	}()
	callback()
	return true
}
