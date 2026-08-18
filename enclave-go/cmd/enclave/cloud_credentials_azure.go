//go:build cloud_azure

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func configureCrossCloudCredentials(boot *types.BootstrapData) error {
	if strings.TrimSpace(boot.GCPServiceAccountKeyJSON) != "" {
		return fmt.Errorf("azure build refuses a GCP service-account credential")
	}
	if strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")) != "" {
		return fmt.Errorf("azure build refuses GOOGLE_APPLICATION_CREDENTIALS")
	}
	return nil
}
