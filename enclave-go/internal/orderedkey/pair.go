// Package orderedkey binds a managed standby decision to a specific ordered
// pair. Only an authenticated control-plane authorization supplies a cutover.
package orderedkey

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

var ErrUnavailable = errors.New("authorized managed credential is unavailable")

// Generation is a commitment, never the credential itself. Delimiters cannot
// occur in provider HTTP credentials. Switching the order changes the binding.
func Generation(provider, primary, standby string) string {
	if provider != "fal" && provider != "minimax" {
		return ""
	}
	primary, standby = strings.TrimSpace(primary), strings.TrimSpace(standby)
	if primary == "" || standby == "" || primary == standby || strings.ContainsAny(primary+standby, "\x00\r\n") {
		return ""
	}
	digest := sha256.Sum256([]byte("tr.ordered-key.v1\x00" + provider + "\x00" + primary + "\x00" + standby))
	return hex.EncodeToString(digest[:])
}

func Select(provider, primary, standby, generation string) (string, error) {
	if generation == "" && strings.TrimSpace(standby) == "" {
		return primary, nil
	}
	if expected, explicit := strings.CutPrefix(generation, "primary:"); explicit {
		if len(expected) != sha256.Size*2 {
			return "", ErrUnavailable
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return "", ErrUnavailable
		}
		if standby == "" || Generation(provider, primary, standby) == expected {
			return primary, nil
		}
		return "", ErrUnavailable
	}
	if generation == "" || Generation(provider, primary, standby) != generation {
		return "", ErrUnavailable
	}
	return strings.TrimSpace(standby), nil
}
