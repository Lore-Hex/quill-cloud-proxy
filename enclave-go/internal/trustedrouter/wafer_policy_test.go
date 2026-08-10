package trustedrouter

import (
	"encoding/json"
	"testing"
)

func TestAuthorizationDecodesWaferZDRPolicy(t *testing.T) {
	var authorization Authorization
	err := json.Unmarshal([]byte(`{
		"wafer_zdr_required": true,
		"route_candidates": [{
			"provider": "wafer",
			"wafer_zdr_required": true
		}]
	}`), &authorization)
	if err != nil {
		t.Fatalf("decode authorization: %v", err)
	}
	if !authorization.WaferZDRRequired {
		t.Fatal("top-level WaferZDRRequired = false, want true")
	}
	if len(authorization.RouteCandidates) != 1 ||
		!authorization.RouteCandidates[0].WaferZDRRequired {
		t.Fatalf("route candidates = %#v", authorization.RouteCandidates)
	}
}
