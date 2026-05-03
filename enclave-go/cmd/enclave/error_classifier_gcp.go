//go:build cloud_gcp

package main

// classifyUpstreamError on GCP — no SDK to unwrap (the Vertex/OpenRouter
// clients hand-roll net/http and produce plain wrapped errors). The
// llm/* package error strings already say which provider they came from
// (e.g. "llm/openrouter: http 402: ..."), so we just surface them.
func classifyUpstreamError(err error) (string, string) {
	return "InternalError", err.Error()
}
