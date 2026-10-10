//go:build !cloud_gcp

package main

import "testing"

func TestNonGCPVertexVideoStaysDisabled(t *testing.T) {
	t.Setenv("QUILL_GCP_PROJECT_ID", "proj")
	if vertexVideoProject() != "" {
		t.Fatal("Vertex Veo must not be enabled off GCP")
	}
}
