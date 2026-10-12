//go:build cloud_gcp && llm_multi

package trustedrouter

// The complete ordered cross-product of decoder-matched spellings runs through
// the real senders in this tag set only: it takes about two minutes under the
// race detector, and member identity is independent of the cloud and model
// tags, so one mandatory CI job carries it.
const shadowIdentityExhaustive = true
