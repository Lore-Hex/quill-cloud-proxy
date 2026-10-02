package shadowobserve

import "time"

type Decision struct {
	CompletedAt time.Duration `json:"completed_at_ns"`
	Eligible    bool          `json:"eligible"`
	Reason      string        `json:"reason"`
	GrantID     string        `json:"grant_id,omitempty"`
	Ordinal     *int64        `json:"ordinal,omitempty"`
	At          time.Duration `json:"at_ns"`
}
