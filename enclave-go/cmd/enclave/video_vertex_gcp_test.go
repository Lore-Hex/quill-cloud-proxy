//go:build cloud_gcp

package main

import "testing"

func TestGCPVertexVideoUsesWorkloadProject(t *testing.T) {
	t.Setenv("QUILL_GCP_PROJECT_ID", "proj")
	if vertexVideoProject() != "proj" || vertexVideoLocation() != "us-central1" {
		t.Fatalf("project=%q location=%q", vertexVideoProject(), vertexVideoLocation())
	}
}
