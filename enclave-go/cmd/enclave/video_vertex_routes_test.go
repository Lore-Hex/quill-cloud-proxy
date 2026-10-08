package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestAuthorizedVideoRoutesCarryUpstreamModel(t *testing.T) {
	auth := &trustedrouter.Authorization{
		Provider: "google-vertex", EndpointID: "ep-vertex", UpstreamModel: "veo-3.1-generate-001",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Provider: "google-ai-studio", EndpointID: "ep-studio", UpstreamModel: "veo-3.1-generate-preview"},
		},
	}
	routes := authorizedVideoRoutes(auth, map[string]videoQuote{
		"google-vertex": {Microdollars: 1}, "google-ai-studio": {Microdollars: 1},
	})
	if len(routes) != 2 || routes[0].Provider != "google-vertex" || routes[0].UpstreamModel != "veo-3.1-generate-001" ||
		routes[1].UpstreamModel != "veo-3.1-generate-preview" {
		t.Fatalf("routes=%#v", routes)
	}
}
