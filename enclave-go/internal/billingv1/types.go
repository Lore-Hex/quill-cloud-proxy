// Package billingv1 implements the dormant frozen billing snapshot v1 contract.
// It performs no catalog reads, network calls, or settlement side effects.
package billingv1

// Rates are customer prices in microdollars per million tokens.
type Rates struct {
	InputMicroPerMillion         int64 `json:"input_micro_per_million"`
	CachedInputMicroPerMillion   int64 `json:"cached_input_micro_per_million"`
	CacheCreationMicroPerMillion int64 `json:"cache_creation_micro_per_million"`
	OutputMicroPerMillion        int64 `json:"output_micro_per_million"`
}

type Tier struct {
	MaxPromptTokens *int64 `json:"max_prompt_tokens"`
	Rates           Rates  `json:"rates"`
}

// Candidate is a detached view of one frozen endpoint. Modifying it cannot
// change the Snapshot from which it was obtained.
type Candidate struct {
	EndpointID          string `json:"endpoint_id" check:"identity"`
	Provider            string `json:"provider" literal:"openai|anthropic"`
	ModelID             string `json:"model_id" check:"identity"`
	UsageType           string `json:"usage_type" literal:"Credits"`
	PriceHistoryVersion int64  `json:"price_history_version" literal:"1"`
	Rates               Rates  `json:"rates"`
	Tiers               []Tier `json:"tiers" bounds:"0,64"`
	RequestFeeMicro     int64  `json:"request_fee_micro"`
	Rounding            string `json:"rounding" literal:"half_up_per_million"`
	PromptConvention    string `json:"prompt_convention" literal:"includes_cache|excludes_cache"`
	OutputConvention    string `json:"output_convention" literal:"includes_reasoning"`
}

type snapshotData struct {
	V             int64       `json:"v" literal:"1"`
	Kind          string      `json:"kind" literal:"credits_endpoint"`
	Candidates    []Candidate `json:"candidates" bounds:"1,64"`
	MinimumCharge string      `json:"minimum_charge" literal:"one_micro_if_positive"`
	ChargeCap     any         `json:"charge_cap" check:"null"`
	TierBasis     string      `json:"tier_basis" literal:"total_prompt"`
	TierBoundary  string      `json:"tier_boundary" literal:"inclusive"`
	TierFallback  string      `json:"tier_fallback" literal:"last_tier"`
}

// Snapshot owns immutable pricing data. Its zero value is invalid; use ParseSnapshot
// or BuildSnapshot. Copies may safely be evaluated concurrently.
type Snapshot struct{ data *snapshotData }

// RawUsage contains provider counts before cache normalization.
type RawUsage struct {
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	CacheReadTokens     int64 `json:"cache_read_tokens" default:"0"`
	CacheCreationTokens int64 `json:"cache_creation_tokens" default:"0"`
	ReasoningTokens     int64 `json:"reasoning_tokens" default:"0"`
}

type NormalizedUsage struct {
	UncachedInputTokens int64 `json:"uncached_input_tokens"`
	TotalPromptTokens   int64 `json:"total_prompt_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	CacheReadTokens     int64 `json:"cache_read_tokens"`
	CacheCreationTokens int64 `json:"cache_creation_tokens"`
	ReasoningTokens     int64 `json:"reasoning_tokens"`
}

type Evaluation struct {
	Usage       NormalizedUsage `json:"usage"`
	ChargeMicro int64           `json:"charge_micro"`
}

// Eligibility contains facts from ONE phase. Callers must provide all requested
// and observed nonordinary features; these facts are not an authorization.
// DefaultEligibility supplies the ordinary typed Credits defaults.
type Eligibility struct {
	Typed            bool    `json:"typed" default:"true"`
	UsageType        string  `json:"usage_type" default:"\"Credits\""`
	Authority        string  `json:"authority" default:"\"local\""`
	RouteType        string  `json:"route_type" default:"\"chat.completions\""`
	Streamed         bool    `json:"streamed" default:"false"`
	ServiceTier      *string `json:"service_tier" default:"null"`
	AppMarkup        int64   `json:"app_markup" default:"0"`
	CustomMarkup     int64   `json:"custom_markup" default:"0"`
	ReceiptFee       int64   `json:"receipt_fee" default:"0"`
	RequestFee       int64   `json:"request_fee" default:"0"`
	CustomModel      bool    `json:"custom_model" default:"false"`
	UserModel        bool    `json:"user_model" default:"false"`
	ToolCost         bool    `json:"tool_cost" default:"false"`
	SearchCost       bool    `json:"search_cost" default:"false"`
	ImageCost        bool    `json:"image_cost" default:"false"`
	VideoCost        bool    `json:"video_cost" default:"false"`
	Partner          bool    `json:"partner" default:"false"`
	Liberty          bool    `json:"liberty" default:"false"`
	NativeBatch      bool    `json:"native_batch" default:"false"`
	Fusion           bool    `json:"fusion" default:"false"`
	Polyphemus       bool    `json:"polyphemus" default:"false"`
	PrivateTierBasis bool    `json:"private_tier_basis" default:"false"`
}

// TerminalEnvelope binds accounting metadata, not ticket authentication or
// persisted authorization identity checks (which belong to later integration).
type TerminalEnvelope struct {
	V                int64           `json:"v" literal:"1"`
	AuthorizationID  string          `json:"authorization_id" check:"identity"`
	GenerationID     string          `json:"generation_id" check:"identity"`
	WorkspaceID      string          `json:"workspace_id" check:"identity"`
	KeyID            string          `json:"key_id" check:"identity"`
	InvocationNonce  string          `json:"invocation_nonce" check:"nonce"`
	BillingAuthority string          `json:"billing_authority" literal:"local"`
	JournalRegion    string          `json:"journal_region" check:"identity"`
	Epoch            int64           `json:"epoch"`
	SelectedEndpoint string          `json:"selected_endpoint" check:"identity"`
	SnapshotVersion  int64           `json:"snapshot_version" literal:"1"`
	SnapshotHash     string          `json:"snapshot_hash" check:"digest"`
	Usage            NormalizedUsage `json:"usage"`
	ChargeMicro      int64           `json:"charge_micro"`
	TerminalKind     string          `json:"terminal_kind" literal:"settle|refund"`
	RouteType        string          `json:"route_type" literal:"chat.completions|responses"`
	Streamed         bool            `json:"streamed"`
}

// AcceptanceOutcome acknowledges pending durable responsibility, never ledger
// finalization. Rejected outcomes cannot carry durability metadata.
type AcceptanceOutcome struct {
	Status           string  `json:"status" literal:"accepted|duplicate|sync_required|conflict|invalid"`
	PayloadHash      *string `json:"payload_hash" check:"digest" default:"null"`
	SettlementStatus *string `json:"settlement_status" literal:"pending" default:"null"`
}
