//go:build cloud_azure

package main

// classifyUpstreamError on Azure — identical reasoning to the GCP variant.
// There is no cloud SDK to unwrap: the llm/* clients hand-roll net/http (the
// dependency-surface rule this binary lives under) and produce plain wrapped
// errors whose strings already name the provider they came from, e.g.
// "llm/openrouter: http 402: ...". So surface them as-is rather than
// re-classifying into a shape that would drop that detail.
func classifyUpstreamError(err error) (string, string) {
	return "InternalError", err.Error()
}
