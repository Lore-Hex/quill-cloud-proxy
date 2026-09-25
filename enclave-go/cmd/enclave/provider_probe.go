package main

import (
	"sync/atomic"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

// One boot-time writer publishes immutable, bounded snapshots. Reading health
// never triggers inference, including on Nitro where stderr is unavailable.
var privatemodeProbeResults atomic.Pointer[[]llm.PrivatemodeProbeResult]

func recordPrivatemodeProbe(result llm.PrivatemodeProbeResult) {
	for {
		previous := privatemodeProbeResults.Load()
		var results []llm.PrivatemodeProbeResult
		if previous != nil {
			if len(*previous) >= 3 {
				return
			}
			results = append(results, (*previous)...)
		}
		results = append(results, result)
		if privatemodeProbeResults.CompareAndSwap(previous, &results) {
			return
		}
	}
}
