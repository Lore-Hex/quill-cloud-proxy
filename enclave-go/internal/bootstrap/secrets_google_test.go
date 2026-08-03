//go:build cloud_gcp || cloud_azure

package bootstrap

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// This file carries the SAME build tag as the code it covers, so the shared
// Secret Manager path is exercised under cloud_gcp as well as cloud_azure.
//
// That matters more than it looks. secrets_google.go has one implementation and
// two callers, and until this file existed only the Azure caller had any tests
// (bootstrap_azure_test.go is //go:build cloud_azure, so `go test -tags
// cloud_gcp ./internal/bootstrap/` reported "no test files"). The whitespace
// regression these tests pin reached the shared file and changed the LIVE GCP
// path, and nothing under cloud_gcp could have caught it.

// clearSecretEnv unsets every variable the binding table reads, plus the three
// scalar ones, so a developer's ambient shell cannot decide the outcome.
func clearSecretEnv(t *testing.T) {
	t.Helper()
	for _, binding := range secretBindings {
		for _, env := range binding.envs {
			t.Setenv(env, "")
		}
	}
	for _, env := range []string{
		"QUILL_GCP_PROJECT_ID", "QUILL_DEVICE_KEYS_SECRET",
		"QUILL_GCP_REGION", "TR_CONTROL_PLANE_BASE_URL",
	} {
		t.Setenv(env, "")
	}
}

func validSecretEnv(t *testing.T) {
	t.Helper()
	clearSecretEnv(t)
	t.Setenv("QUILL_GCP_PROJECT_ID", "quill-cloud-proxy")
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", "tr-device-keys")
	t.Setenv("QUILL_OPENROUTER_SECRET", "tr-openrouter-key")
}

// A secret NAME that is present but blank is a broken deploy. Skipping it boots
// a gateway whose key for that provider is "" and which 401s every request to
// it at runtime; the pre-refactor GCP code fetched a secret literally named
// "   " and died 404 at boot. Failing here is louder than both — it happens
// before any network I/O and names the variable.
func TestResolveSecretConfigRejectsWhitespaceOnlyValues(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"QUILL_GCP_PROJECT_ID", "QUILL_GCP_PROJECT_ID"},
		{"QUILL_DEVICE_KEYS_SECRET", "QUILL_DEVICE_KEYS_SECRET"},
		{"QUILL_ANTHROPIC_SECRET", "QUILL_ANTHROPIC_SECRET"},
		{"QUILL_TRUSTEDROUTER_INTERNAL_SECRET", "QUILL_TRUSTEDROUTER_INTERNAL_SECRET"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			validSecretEnv(t)
			t.Setenv(tc.env, " \t\n ")

			_, err := resolveSecretConfig("bootstrap/gcp")
			if err == nil {
				t.Fatalf("%s set to whitespace booted cleanly", tc.env)
			}
			for _, want := range []string{"bootstrap/gcp", tc.want, "whitespace only"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %q\n  got: %v", want, err)
				}
			}
		})
	}
}

// An empty value still means "not configured": that is how a container spec
// says "off", and the pre- and post-refactor code agree on it.
func TestResolveSecretConfigTreatsEmptyAsUnset(t *testing.T) {
	validSecretEnv(t)

	cfg, err := resolveSecretConfig("bootstrap/gcp")
	if err != nil {
		t.Fatalf("resolveSecretConfig: %v", err)
	}
	for i, binding := range secretBindings {
		want := ""
		if binding.envs[0] == "QUILL_OPENROUTER_SECRET" {
			want = "tr-openrouter-key"
		}
		if cfg.names[i] != want {
			t.Errorf("%s -> %q, want %q", binding.label, cfg.names[i], want)
		}
	}
}

// The advisor bindings accept a pre-rename spelling; an empty first variable
// must still fall through to it.
func TestResolveSecretConfigFallsThroughToLegacyEnvNames(t *testing.T) {
	validSecretEnv(t)
	t.Setenv("QUILL_SOCRATES_ADVISOR_PROMPT_SECRET", "tr-advisor-prompt")
	t.Setenv("QUILL_SOCRATES_WORKER_PROMPT_SECRET", "tr-advisor-worker-prompt")

	cfg, err := resolveSecretConfig("bootstrap/gcp")
	if err != nil {
		t.Fatalf("resolveSecretConfig: %v", err)
	}
	got := map[string]string{}
	for i, binding := range secretBindings {
		got[binding.label] = cfg.names[i]
	}
	if got["advisor prompt"] != "tr-advisor-prompt" {
		t.Errorf("advisor prompt = %q", got["advisor prompt"])
	}
	if got["advisor worker prompt"] != "tr-advisor-worker-prompt" {
		t.Errorf("advisor worker prompt = %q", got["advisor worker prompt"])
	}
}

// The newer spelling wins when both are set.
func TestResolveSecretConfigPrefersTheCurrentEnvName(t *testing.T) {
	validSecretEnv(t)
	t.Setenv("QUILL_ADVISOR_PROMPT_SECRET", "current")
	t.Setenv("QUILL_SOCRATES_ADVISOR_PROMPT_SECRET", "legacy")

	cfg, err := resolveSecretConfig("bootstrap/gcp")
	if err != nil {
		t.Fatalf("resolveSecretConfig: %v", err)
	}
	for i, binding := range secretBindings {
		if binding.label == "advisor prompt" && cfg.names[i] != "current" {
			t.Errorf("advisor prompt = %q, want the current spelling to win", cfg.names[i])
		}
	}
}

// A deploy with prompt overrides and a control-plane token but no provider key
// has no LLM backend at all. It must fail at boot rather than serve a gateway
// that 500s every request.
func TestResolveSecretConfigRequiresAProviderSecret(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("QUILL_GCP_PROJECT_ID", "quill-cloud-proxy")
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", "tr-device-keys")
	t.Setenv("QUILL_SYNTH_PANEL_PROMPT_SECRET", "tr-synth-panel")
	t.Setenv("QUILL_TRUSTEDROUTER_INTERNAL_SECRET", "tr-internal")

	if _, err := resolveSecretConfig("bootstrap/gcp"); err == nil ||
		!strings.Contains(err.Error(), "at least one provider secret") {
		t.Fatalf("want the provider guard to fire, got %v", err)
	}
}

// Every binding must write to its OWN field. A copy-paste in a 39-row table is
// how one provider's API key ends up being sent to another provider's endpoint,
// and nothing else in the suite would notice: the fetch would succeed and the
// wrong key would only fail much later, at the upstream.
func TestSecretBindingsAssignDistinctFields(t *testing.T) {
	seen := map[string]string{} // field name -> binding label
	for _, binding := range secretBindings {
		marker := "MARKER-" + binding.label
		var data types.BootstrapData
		binding.assign(&data, marker)

		value := reflect.ValueOf(data)
		var hit []string
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.Kind() == reflect.String && field.String() == marker {
				hit = append(hit, value.Type().Field(i).Name)
			}
		}
		if len(hit) != 1 {
			t.Errorf("%q writes %d fields (%v), want exactly 1", binding.label, len(hit), hit)
			continue
		}
		if other, dup := seen[hit[0]]; dup {
			t.Errorf("%q and %q both write BootstrapData.%s", other, binding.label, hit[0])
		}
		seen[hit[0]] = binding.label
	}
}

// Structural pins on the table itself, so a bad edit is caught here rather than
// three weeks later on one cloud only. The counts reproduce the hand-written
// sequence bootstrap_gcp.go used before secrets_google.go existed: 32 provider
// keys in the anySet list, 4 synth prompts, 2 advisor prompts, 1 TR token.
func TestSecretBindingsTableIsWellFormed(t *testing.T) {
	if len(secretBindings) != 39 {
		t.Errorf("secretBindings has %d entries, want 39", len(secretBindings))
	}
	providers := 0
	envs := map[string]string{}
	for _, binding := range secretBindings {
		if binding.provider {
			providers++
		}
		if binding.label == "" || binding.assign == nil || len(binding.envs) == 0 {
			t.Errorf("malformed binding %+v", binding.envs)
		}
		for _, env := range binding.envs {
			if other, dup := envs[env]; dup {
				t.Errorf("%s is read by both %q and %q", env, other, binding.label)
			}
			envs[env] = binding.label
		}
	}
	if providers != 32 {
		t.Errorf("%d provider bindings, want 32 — the 'at least one provider' guard counts these", providers)
	}
}

func TestFirstSetEnvErrorNamesTheOffendingVariable(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv("QUILL_ADVISOR_PROMPT_SECRET", "  ")
	t.Setenv("QUILL_SOCRATES_ADVISOR_PROMPT_SECRET", "legacy")

	// The blank value must NOT fall through to the legacy spelling: silently
	// using a different secret than the one the operator named is worse than
	// refusing to boot.
	value, err := firstSetEnv([]string{"QUILL_ADVISOR_PROMPT_SECRET", "QUILL_SOCRATES_ADVISOR_PROMPT_SECRET"})
	if err == nil {
		t.Fatalf("want an error, got value %q", value)
	}
	if !strings.Contains(err.Error(), "QUILL_ADVISOR_PROMPT_SECRET") {
		t.Errorf("error does not name the variable: %v", err)
	}
}
