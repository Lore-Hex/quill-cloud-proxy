//go:build cloud_gcp

package main

import (
	"os"
	"strings"
)

// Vertex Veo authenticates with the Confidential Space workload identity via
// the GCE metadata server, exactly like internal/llm's Vertex clients, so it
// is only wired on GCP builds.
func vertexVideoProject() string { return strings.TrimSpace(os.Getenv("QUILL_GCP_PROJECT_ID")) }

func vertexVideoLocation() string {
	if location := strings.TrimSpace(os.Getenv("QUILL_VEO_VERTEX_REGION")); location != "" {
		return location
	}
	return "us-central1"
}
