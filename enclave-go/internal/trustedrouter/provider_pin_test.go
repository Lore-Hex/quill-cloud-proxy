package trustedrouter

import (
	"context"
	"net/http"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestProviderPinIsInheritedAndCanOnlyNarrow(t *testing.T) {
	with := func(ctx context.Context, ids ...string) context.Context {
		return WithRequestPrivacy(ctx, "", nil, &qtypes.ProviderRouting{Only: ids})
	}
	pin := with(t.Context(), " Google ", "tinfoil")
	if ConfidentialOnly(pin) {
		t.Fatal("a provider filter is not a privacy tier")
	}
	for _, id := range []string{"google-ai-studio", "google-vertex", "tinfoil"} {
		if !ProviderPinAllows(pin, id) {
			t.Fatalf("missing eligible provider %q", id)
		}
	}
	for _, id := range []string{"", "Google", "gemini", "openai"} {
		if ProviderPinAllows(pin, id) {
			t.Fatalf("accepted noncanonical or excluded provider %q", id)
		}
	}
	child := with(pin, "vertex_ai", "openai")
	child = WithRequestPrivacy(child, "", nil, nil)
	if !ProviderPinAllows(child, "google-vertex") || ProviderPinAllows(child, "openai") || ProviderPinAllows(child, "tinfoil") {
		t.Fatal("child changed the caller's selection")
	}
	empty := with(with(child, "tinfoil"), "tinfoil")
	if !HasProviderPin(empty) || ProviderPinAllows(empty, "tinfoil") || ProviderPinAllows(empty, "google-vertex") {
		t.Fatal("empty intersection broadened")
	}
}

func TestProviderPinRejectsIncompatibleLeaseBeforeSpeculation(t *testing.T) {
	client, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", http.StatusOK, nil)
	ctx := WithRequestPrivacy(fixedStageCContext(), "", nil, &qtypes.ProviderRouting{Only: []string{"openai"}})
	plan, err := client.PrepareSpendLeaseAdmission(ctx, "sk-stage-c-fixture", stageCFixtureRequest(), "chat.completions", time.UnixMilli(2_000_000_005_000))
	if err != nil || plan != nil {
		t.Fatalf("incompatible inherited pin must miss local admission, got plan=%v err=%v", plan != nil, err)
	}
}

func TestProviderPinChecksPrimaryFallbackCredentialAndDispatch(t *testing.T) {
	for _, base := range []context.Context{t.Context(), WithTrustedOnly(t.Context())} {
		ctx := WithRequestPrivacy(base, "", nil, &qtypes.ProviderRouting{Only: []string{"tinfoil"}})
		a := Authorization{Provider: "tinfoil", Model: "openai/gpt-oss-120b", UpstreamModel: "gpt-oss-120b", UsageType: "Credits"}
		good := RouteCandidate{Provider: a.Provider, Model: a.Model, UpstreamModel: a.UpstreamModel, UsageType: a.UsageType}
		a.RouteCandidates = []RouteCandidate{good}
		if err := validateConfidentialAuthorization(ctx, &a); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*Authorization){
			func(b *Authorization) { b.Provider = "" },
			func(b *Authorization) { b.Provider = "privatemode" },
			func(b *Authorization) { b.BYOKProvider = "privatemode" },
			func(b *Authorization) {
				b.RouteCandidates = append(b.RouteCandidates, RouteCandidate{Provider: "privatemode"})
			},
			func(b *Authorization) {
				c := good
				c.BYOKProvider = "privatemode"
				b.RouteCandidates = []RouteCandidate{c}
			},
		} {
			b := a
			change(&b)
			if err := validateConfidentialAuthorization(ctx, &b); err == nil || err.Type != "provider_pin_unavailable" {
				t.Fatalf("wrong route-pin result: %v", err)
			}
		}
		if !PrivateDispatchAllowed(ctx, a.Provider, a.Model, a.UpstreamModel, a.UsageType, false) ||
			PrivateDispatchAllowed(ctx, "privatemode", "z-ai/glm-5.3", "glm-5.3", "Credits", false) {
			t.Fatal("dispatch disagrees with the caller's provider pin")
		}
	}
}
