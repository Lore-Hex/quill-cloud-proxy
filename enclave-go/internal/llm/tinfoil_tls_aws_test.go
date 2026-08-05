//go:build cloud_aws

package llm

import "testing"

func TestAWSTinfoilDataPathIsAllowlisted(t *testing.T) {
	t.Parallel()
	for _, tunnel := range AWSProviderTunnels() {
		if tunnel.Host == tinfoilEnclaveHost {
			if tunnel.Port != 8017 {
				t.Fatalf("Tinfoil tunnel port = %d, want 8017", tunnel.Port)
			}
			return
		}
	}
	t.Fatal("AWS provider tunnels do not include Tinfoil")
}
