//go:build cloud_azure

package bootstrap

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// The GCP and Azure bootstrap paths each carry their own provider list, and
// this test is the only thing stopping them forking.
//
// WHY THERE ARE TWO LISTS. The azure branch originally refactored
// bootstrap_gcp.go to share one resolver. Bringing that forward would have
// meant rewriting GCP's live secret-loading path — 486 extracted lines —
// against a bootstrap_gcp.go that had since gained 17 providers. A subtle
// mistake there produces an enclave that boots green and 401s at runtime on
// whichever providers were dropped, which is close to the worst failure shape
// available: invisible until a customer hits that route.
//
// So GCP keeps its loader untouched and Azure is self-contained. The price is
// duplication, and this test is what converts that price from "silent fork" to
// "CI failure". It reads both files as TEXT rather than importing them, because
// they are behind mutually exclusive build tags and can never be linked into
// the same binary.
//
// If this fails: a provider was added to one cloud and not the other. Add it to
// the other. Do NOT relax the assertion — a provider missing on one cloud is
// exactly the bug this exists to catch.
func TestProviderSecretParityAcrossClouds(t *testing.T) {
	secretName := regexp.MustCompile(`"(QUILL_[A-Z0-9_]+_SECRET)"`)

	read := func(path string) map[string]bool {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		out := map[string]bool{}
		for _, m := range secretName.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
		if len(out) == 0 {
			t.Fatalf("%s: parsed no secret names — did the binding shape change? "+
				"A guard that silently matches nothing is worse than no guard.", path)
		}
		return out
	}

	gcp := read("bootstrap_gcp.go")
	azure := read("secrets.go")

	var missingOnAzure, missingOnGCP []string
	for name := range gcp {
		if !azure[name] {
			missingOnAzure = append(missingOnAzure, name)
		}
	}
	for name := range azure {
		if !gcp[name] {
			missingOnGCP = append(missingOnGCP, name)
		}
	}
	sort.Strings(missingOnAzure)
	sort.Strings(missingOnGCP)

	if len(missingOnAzure) > 0 {
		t.Errorf("%d provider secret(s) resolved on GCP but NOT on Azure — those providers "+
			"would 401 at runtime on Azure while the enclave boots healthy: %v",
			len(missingOnAzure), missingOnAzure)
	}
	if len(missingOnGCP) > 0 {
		t.Errorf("%d provider secret(s) resolved on Azure but NOT on GCP: %v",
			len(missingOnGCP), missingOnGCP)
	}
}
