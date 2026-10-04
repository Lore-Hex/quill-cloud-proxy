package shadowobserve

import "context"

type Refresh func(context.Context, []Identity) ([]Result, *Miss)
type Observer interface {
	Run(context.Context, Refresh)
	Excluded(string) *Execution
	ObserveAuthorized(Identity)
	ObserveVerdict(string, int, string, string)
	Suppressed(string)
	Records() <-chan Record
}
