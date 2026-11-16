//go:build cloud_aws

package llm

import "testing"

func TestContextDevAWSTunnel(t *testing.T) {
	matches := 0
	for _, tunnel := range AWSProviderTunnels() {
		if tunnel.Host != "api.context.dev" {
			continue
		}
		matches++
		if tunnel.CID != 3 || tunnel.Port != 8138 {
			t.Fatalf("context.dev tunnel = %+v, want parent CID 3 port 8138", tunnel)
		}
	}
	if matches != 1 {
		t.Fatalf("context.dev tunnel count = %d, want one", matches)
	}
}
