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

// vertexVideoLocation is fixed: Veo is served from us-central1 on Vertex, and
// a new env knob would also need a Confidential Space launch-policy entry.
func vertexVideoLocation() string { return "us-central1" }
