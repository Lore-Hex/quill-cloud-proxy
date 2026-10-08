//go:build cloud_gcp

package main

import "testing"

func TestGCPVertexVideoUsesWorkloadProject(t *testing.T) {
	t.Setenv("QUILL_GCP_PROJECT_ID", "proj")
	t.Setenv("QUILL_VEO_VERTEX_REGION", "")
	if vertexVideoProject() != "proj" || vertexVideoLocation() != "us-central1" {
		t.Fatalf("project=%q location=%q", vertexVideoProject(), vertexVideoLocation())
	}
}
