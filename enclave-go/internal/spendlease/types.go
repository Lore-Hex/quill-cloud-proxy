// Package spendlease implements the enclave-side spend-lease protocol. Stage A
// grants remain shadow-only; Stage C can make an authoritative grant
// consequential only behind the separately measured local-admission flag.
package spendlease

import "time"

const (
	JWSType          = "spend-lease+jws"
	AdmissionJWSType = "spend_lease_admission+jws"
	Cohort           = "credits-chat-v1"
	ConfigV1         = 1
	Skew             = 10 * time.Second
	MaximumTTL       = 60 * time.Second
	ReserveBudget    = 28 * time.Second
	AdmissionMargin  = 28 * time.Second
	AuthorizePath    = "/internal/gateway/authorize"
	RegisterPath     = "/internal/gateway/spend-lease/register-boot"
)

// Fail compilation if a future retry-budget increase crosses the admission
// margin without also revisiting the router allocation deadline proof.
const _ uint64 = uint64(AdmissionMargin - ReserveBudget)

type JWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
}

// IssuerConfig is the attested Secret Manager blob named by launch config.
// Validity bounds are inclusive Unix seconds and apply to a token's iat.
type IssuerConfig struct {
	Version int         `json:"version"`
	Keys    []IssuerKey `json:"keys"`
}

type IssuerKey struct {
	KID       string `json:"kid"`
	JWK       JWK    `json:"jwk"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
}

type Claims struct {
	Version               int     `json:"v"`
	Type                  string  `json:"typ"`
	Authoritative         bool    `json:"authoritative"`
	LocalAdmissionAllowed bool    `json:"local_admission_allowed"`
	RoutingPolicyHash     string  `json:"routing_policy_hash"`
	LeaseID               string  `json:"lease_id"`
	KeyHash               string  `json:"key_hash"`
	WorkspaceID           string  `json:"workspace_id"`
	Cohort                string  `json:"cohort"`
	CapMicro              int64   `json:"cap_micro"`
	Generation            int64   `json:"gen"`
	IssuedAt              int64   `json:"iat"`
	ExpiresAt             int64   `json:"exp"`
	BootKID               string  `json:"boot_kid"`
	Catalog               Catalog `json:"catalog"`
}

type Catalog struct {
	Version    string      `json:"version"`
	Candidates []Candidate `json:"candidates"`
}

type Candidate struct {
	EndpointID              string `json:"endpoint_id"`
	Model                   string `json:"model"`
	UpstreamModel           string `json:"upstream_model"`
	Provider                string `json:"provider"`
	UsageType               string `json:"usage_type"`
	WaferZDRRequired        bool   `json:"wafer_zdr_required"`
	Region                  string `json:"region"`
	RouteType               string `json:"route_type"`
	ServiceTier             string `json:"service_tier"`
	PriceTierMaxInputTokens *int64 `json:"price_tier_max_input_tokens"`
	InputPriceMicroPerMTok  int64  `json:"input_price_micro_per_mtok"`
	OutputPriceMicroPerMTok int64  `json:"output_price_micro_per_mtok"`
	RequestPriceMicro       int64  `json:"request_price_micro"`
	CacheReadMicroPerMTok   int64  `json:"cache_read_micro_per_mtok"`
	CacheWriteMicroPerMTok  int64  `json:"cache_write_micro_per_mtok"`
}

type VerifiedLease struct {
	Claims     Claims
	Deadline   time.Time
	AdmitUntil time.Time
}

type Response struct {
	Token          *string `json:"token"`
	LeaseStatus    string  `json:"lease_status"`
	RemainingMicro *int64  `json:"remaining_micro,omitempty"`
}

type Echo struct {
	LeaseID              *string `json:"lease_id"`
	State                string  `json:"state"`
	RemainingMicro       *int64  `json:"remaining_micro"`
	EnclaveEstimateMicro *int64  `json:"enclave_estimate_micro"`
	CatalogVersion       *string `json:"catalog_version"`
	WouldAdmit           *bool   `json:"would_admit"`
}

type BootAuth struct {
	KID string `json:"kid"`
	Sig string `json:"sig"`
}

type EstimateRequest struct {
	Model                string   `json:"model"`
	ProviderConstraints  []string `json:"provider_constraints,omitempty"`
	RouteType            string   `json:"route_type"`
	Region               string   `json:"region"`
	ServiceTier          string   `json:"service_tier"`
	EstimatedInputTokens int64    `json:"estimated_input_tokens"`
	MaxTokens            *int64   `json:"max_tokens"`
}

// AdmissionReceiptClaims is declaration-ordered by JSON name to pin the
// router's canonical compact-JWS payload. Integers remain JSON integers.
type AdmissionReceiptClaims struct {
	AdmittedAtMS         int64  `json:"admitted_at_ms"`
	BootKID              string `json:"boot_kid"`
	EnclaveEstimateMicro int64  `json:"enclave_estimate_micro"`
	Generation           int64  `json:"gen"`
	IdempotencyKeySHA256 string `json:"idempotency_key_sha256"`
	KeyHash              string `json:"key_hash"`
	LeaseID              string `json:"lease_id"`
	RemainingAfterMicro  int64  `json:"remaining_after_micro"`
	RoutingPolicyHash    string `json:"routing_policy_hash"`
	Version              int    `json:"v"`
	WorkspaceID          string `json:"workspace_id"`
}

// Admission is the immutable result of one consequential CAS decrement.
// Release must be called after the reserve completes so the best-effort scope
// dedupe does not grow without bound.
type Admission struct {
	Receipt             string
	ReceiptHash         string
	Scope               string
	Lease               VerifiedLease
	EstimateMicro       int64
	RemainingAfterMicro int64
	Echo                Echo
	release             func()
}

func (a *Admission) Release() {
	if a != nil && a.release != nil {
		a.release()
		a.release = nil
	}
}

type AdmissionMarker struct {
	Accepted    bool   `json:"accepted"`
	ReceiptHash string `json:"receipt_hash"`
}
