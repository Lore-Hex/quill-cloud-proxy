// Package spendlease implements the enclave-side Stage A spend-lease
// protocol. Stage A is shadow-only: verified grants can produce evidence and
// simulated decrements, but can never authorize provider work.
package spendlease

import "time"

const (
	JWSType       = "spend-lease+jws"
	Cohort        = "credits-chat-v1"
	ConfigV1      = 1
	Skew          = 10 * time.Second
	MaximumTTL    = 60 * time.Second
	AuthorizePath = "/internal/gateway/authorize"
	RegisterPath  = "/internal/gateway/spend-lease/register-boot"
)

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
	Version       int     `json:"v"`
	Type          string  `json:"typ"`
	Authoritative bool    `json:"authoritative"`
	LeaseID       string  `json:"lease_id"`
	KeyHash       string  `json:"key_hash"`
	WorkspaceID   string  `json:"workspace_id"`
	Cohort        string  `json:"cohort"`
	CapMicro      int64   `json:"cap_micro"`
	Generation    int64   `json:"gen"`
	IssuedAt      int64   `json:"iat"`
	ExpiresAt     int64   `json:"exp"`
	BootKID       string  `json:"boot_kid"`
	Catalog       Catalog `json:"catalog"`
}

type Catalog struct {
	Version    string      `json:"version"`
	Candidates []Candidate `json:"candidates"`
}

type Candidate struct {
	EndpointID              string `json:"endpoint_id"`
	Model                   string `json:"model"`
	Provider                string `json:"provider"`
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
	Claims   Claims
	Deadline time.Time
}

type Response struct {
	Token       *string `json:"token"`
	LeaseStatus string  `json:"lease_status"`
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
