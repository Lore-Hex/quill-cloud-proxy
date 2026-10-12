//go:build !(cloud_gcp && llm_multi)

package trustedrouter

// See async_shadow_identity_exhaustive_test.go: these tag sets run the bounded
// deterministic pair selection.
const shadowIdentityExhaustive = false
