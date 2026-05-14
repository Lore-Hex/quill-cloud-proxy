package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

type providerCircuitRegistry struct {
	mu        sync.Mutex
	enabled   bool
	threshold int
	openFor   time.Duration
	now       func() time.Time
	states    map[string]providerCircuitState
}

type providerCircuitState struct {
	failures  int
	openUntil time.Time
}

func newProviderCircuitRegistryFromEnv() *providerCircuitRegistry {
	enabled := strings.ToLower(strings.TrimSpace(os.Getenv("QUILL_PROVIDER_CIRCUIT_BREAKER"))) != "false"
	threshold := circuitEnvInt("QUILL_PROVIDER_CIRCUIT_FAILURE_THRESHOLD", 3)
	openSeconds := circuitEnvInt("QUILL_PROVIDER_CIRCUIT_OPEN_SECONDS", 60)
	if threshold < 1 {
		threshold = 1
	}
	if openSeconds < 1 {
		openSeconds = 1
	}
	return &providerCircuitRegistry{
		enabled:   enabled,
		threshold: threshold,
		openFor:   time.Duration(openSeconds) * time.Second,
		now:       time.Now,
		states:    map[string]providerCircuitState{},
	}
}

func circuitEnvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func (r *providerCircuitRegistry) Allow(option llm.InvokeOptions) bool {
	if r == nil || !r.enabled {
		return true
	}
	key := providerCircuitKey(option)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.states[key]
	if !ok || state.openUntil.IsZero() || !now.Before(state.openUntil) {
		return true
	}
	return false
}

func (r *providerCircuitRegistry) RecordSuccess(option llm.InvokeOptions) {
	if r == nil || !r.enabled {
		return
	}
	key := providerCircuitKey(option)
	r.mu.Lock()
	delete(r.states, key)
	r.mu.Unlock()
}

func (r *providerCircuitRegistry) RecordFailure(option llm.InvokeOptions) bool {
	if r == nil || !r.enabled {
		return false
	}
	key := providerCircuitKey(option)
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.states[key]
	state.failures++
	opened := false
	if state.failures >= r.threshold {
		state.openUntil = r.now().Add(r.openFor)
		opened = true
	}
	r.states[key] = state
	return opened
}

func providerCircuitKey(option llm.InvokeOptions) string {
	provider := strings.TrimSpace(option.Provider)
	if provider == "" {
		provider = "unknown"
	}
	region := currentRegion()
	modelFamily := providerCircuitModelFamily(option.Model)
	return provider + "|" + region + "|" + modelFamily
}

func providerCircuitModelFamily(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return "unknown"
	}
	if before, _, ok := strings.Cut(model, ":"); ok {
		model = before
	}
	parts := strings.Split(model, "/")
	if len(parts) < 2 {
		return model
	}
	slug := parts[1]
	for _, sep := range []string{"-", "_", "."} {
		if idx := strings.Index(slug, sep); idx > 0 {
			slug = slug[:idx]
			break
		}
	}
	return parts[0] + "/" + slug
}

func currentRegion() string {
	for _, name := range []string{"TR_REGION", "GCP_REGION", "AWS_REGION"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return "unknown"
}

var providerCircuits = newProviderCircuitRegistryFromEnv()
