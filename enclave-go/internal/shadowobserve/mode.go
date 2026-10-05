// Package shadowobserve observes ordinary execution. It has no dispatch or billing authority.
package shadowobserve

import "fmt"

type Mode string

const (
	Off    Mode = "off"
	Shadow Mode = "shadow"
)

func ParseMode(raw string) (Mode, error) {
	switch raw {
	case "", "off":
		return Off, nil
	case "shadow":
		return Shadow, nil
	case "enforce":
		return "", fmt.Errorf("speculative provider enforce is unavailable until PR 15")
	default:
		return "", fmt.Errorf("invalid QUILL_SPECULATIVE_PROVIDER_MODE: expected off or shadow")
	}
}
