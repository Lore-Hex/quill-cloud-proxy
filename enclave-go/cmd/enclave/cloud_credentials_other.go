//go:build !cloud_azure

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func configureCrossCloudCredentials(boot *types.BootstrapData) error {
	if strings.TrimSpace(boot.GCPServiceAccountKeyJSON) == "" {
		return nil
	}
	credPath := "/tmp/gcp-sa.json" // #nosec G101 -- fixed tmpfs path, not a credential.
	if err := os.WriteFile(credPath, []byte(boot.GCPServiceAccountKeyJSON), 0o600); err != nil {
		return fmt.Errorf("write GCP SA key tmpfs: %w", err)
	}
	if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credPath); err != nil {
		return fmt.Errorf("set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
	}
	fmt.Fprintf(os.Stderr, "cross-cloud SA key wired: GOOGLE_APPLICATION_CREDENTIALS=%s\n", credPath)
	return nil
}
