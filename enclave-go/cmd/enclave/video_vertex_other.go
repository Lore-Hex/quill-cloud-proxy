//go:build !cloud_gcp

package main

// Azure refuses GCP credentials and has no GCE metadata server; AWS Nitro has
// no aiplatform tunnel. Vertex Veo stays disabled off GCP.
func vertexVideoProject() string  { return "" }
func vertexVideoLocation() string { return "" }
