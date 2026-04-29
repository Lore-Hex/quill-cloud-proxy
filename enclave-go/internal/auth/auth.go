// Package auth holds the device-key registry. Bearer hash → DeviceConfig
// lookup is constant-time. The map is loaded once at boot from the
// bootstrap RPC and is read-only thereafter (V1; V1.1 will add a refresh
// channel for fast revocation without restarts).
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Registry holds the key-hash → device map.
type Registry struct {
	mu      sync.RWMutex
	devices map[string]types.DeviceConfig // key_hash (hex) → cfg
}

// New builds a registry from a list of devices.
func New(devices []types.DeviceConfig) *Registry {
	m := make(map[string]types.DeviceConfig, len(devices))
	for _, d := range devices {
		m[d.KeyHash] = d
	}
	return &Registry{devices: m}
}

// Lookup hashes the bearer and returns the matching device or nil if absent.
// Uses constant-time compare across all entries to avoid timing leaks.
func (r *Registry) Lookup(bearer string) *types.DeviceConfig {
	digest := sha256.Sum256([]byte(bearer))
	want := hex.EncodeToString(digest[:])
	r.mu.RLock()
	defer r.mu.RUnlock()
	var match *types.DeviceConfig
	for hash, cfg := range r.devices {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(want)) == 1 {
			c := cfg
			match = &c
			// Keep iterating so the timing isn't dependent on early exit.
		}
	}
	return match
}

// Replace atomically swaps the device map. Used by the future polling refresh.
func (r *Registry) Replace(devices []types.DeviceConfig) {
	m := make(map[string]types.DeviceConfig, len(devices))
	for _, d := range devices {
		m[d.KeyHash] = d
	}
	r.mu.Lock()
	r.devices = m
	r.mu.Unlock()
}
