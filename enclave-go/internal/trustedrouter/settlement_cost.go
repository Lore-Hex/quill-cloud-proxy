package trustedrouter

import "encoding/json"

func (r *SettleResult) HasCost() bool {
	return r != nil && (r.CostMicrodollarsKnown || r.CostMicrodollars != 0)
}

func (r *SettleResult) UnmarshalJSON(data []byte) error {
	type plain SettleResult
	var decoded struct {
		plain
		CostMicrodollars *int `json:"cost_microdollars"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = SettleResult(decoded.plain)
	if decoded.CostMicrodollars != nil {
		r.CostMicrodollars = *decoded.CostMicrodollars
		r.CostMicrodollarsKnown = true
	}
	return nil
}

func (r SettleResult) MarshalJSON() ([]byte, error) {
	type plain SettleResult
	var cost *int
	if r.HasCost() {
		cost = &r.CostMicrodollars
	}
	return json.Marshal(struct {
		plain
		CostMicrodollars *int `json:"cost_microdollars,omitempty"`
	}{plain(r), cost})
}
