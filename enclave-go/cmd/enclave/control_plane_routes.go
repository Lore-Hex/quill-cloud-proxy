package main

import "strings"

// controlPlaneRouteMessage identifies account/management routes registered by
// quill-router under /v1. Match a complete path segment, leaving /v1/key and
// gateway inference/catalog routes alone. Use only static roots in the hint:
// path suffixes and query strings may contain credentials or private IDs.
func controlPlaneRouteMessage(path string) string {
	rest, ok := strings.CutPrefix(path, "/v1/")
	if !ok {
		return ""
	}
	root, _, _ := strings.Cut(rest, "/")
	subject := "Account management"
	switch root {
	case "keys":
		subject = "Key management"
	case "credits", "activity", "workspaces", "organization", "billing", "byok", "custom-models", "broadcast", "auth", "signup", "generation":
	default:
		return ""
	}
	return subject + " is served at https://trustedrouter.com/v1/" + root + ", not api.trustedrouter.com"
}
