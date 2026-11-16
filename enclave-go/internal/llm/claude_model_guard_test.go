package llm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// claudeAlias marks a string that names no model: a "latest" alias the fusion
// tables resolve to a concrete ID, itself listed below, before any dispatch.
const claudeAlias = "alias"

// knownClaudeModelClasses lists every Claude model ID written in the
// enclave's non-test Go source, with the reasoning class it must have. The
// classes are documented in docs/reasoning-output.md, "Claude models".
//
// An ID that is not here fails TestEveryKnownClaudeModelHasAReasoningClass.
// That is the point: a Claude model no class names takes the budget path, and
// the newer models refuse budget thinking outright (Haiku 5.5 answered every
// effort with a 400 until it was listed). Before adding an ID, find out which
// thinking and effort values the model accepts, then name its class here and,
// unless it is budget-only, in claudeReasoningModels.
var knownClaudeModelClasses = map[string]string{
	// Catalog IDs.
	"anthropic/claude-3-5-sonnet": "budget",
	"anthropic/claude-haiku-4.5":  "budget",
	"anthropic/claude-opus-4":     "budget",
	"anthropic/claude-opus-4.1":   "budget",
	"anthropic/claude-sonnet-4":   "budget",
	"anthropic/claude-sonnet-4.5": "budget",
	"anthropic/claude-opus-4.5":   "opus45",
	"anthropic/claude-sonnet-4.6": "v46",
	"anthropic/claude-opus-4.7":   "full",
	"anthropic/claude-opus-4.8":   "full",
	"anthropic/claude-sonnet-5":   "full",
	"anthropic/claude-sonnet-5.5": "full",
	"anthropic/claude-opus-5.5":   "full",
	"anthropic/claude-haiku-5.5":  "full",
	"anthropic/claude-fable-5.1":  "full",
	// Anthropic IDs.
	"claude-3-5-sonnet-20241022": "budget",
	"claude-haiku-4-5":           "budget",
	"claude-haiku-4-5-20251001":  "budget",
	"claude-opus-4-20250514":     "budget",
	"claude-opus-4-1-20250805":   "budget",
	"claude-sonnet-4-20250514":   "budget",
	"claude-sonnet-4-5-20250929": "budget",
	"claude-opus-4-5-20251101":   "opus45",
	"claude-sonnet-4-6":          "v46",
	"claude-opus-4-7":            "full",
	"claude-opus-4-8":            "full",
	"claude-sonnet-5":            "full",
	// Bedrock profiles.
	"us.anthropic.claude-haiku-4-5-20251001-v1:0": "budget",
	"us.anthropic.claude-sonnet-4-6":              "v46",
	"us.anthropic.claude-opus-4-7":                "full",
	"us.anthropic.claude-opus-4-8":                "full",
	"us.anthropic.claude-sonnet-5":                "full",
	"us.anthropic.claude-sonnet-5-5":              "full",
	"us.anthropic.claude-opus-5-5":                "full",
	"us.anthropic.claude-haiku-5-5":               "full",
	// The class table's own match strings in anthropic_reasoning.go.
	"claude-opus-4-5":   "opus45",
	"claude-opus-4-6":   "v46",
	"claude-opus-5":     "full",
	"claude-sonnet-5-5": "full",
	"claude-haiku-5":    "full",
	"claude-fable-5":    "full",
	"claude-mythos-5":   "full",
	// Fusion aliases.
	"~anthropic/claude-latest":        claudeAlias,
	"~anthropic/claude-opus-latest":   claudeAlias,
	"~anthropic/claude-sonnet-latest": claudeAlias,
	"~anthropic/claude-haiku-latest":  claudeAlias,
}

var claudeModelLiteral = regexp.MustCompile(`^(~?anthropic/|us\.anthropic\.)?claude-[a-z0-9][a-z0-9.:@-]*$`)

// claudeModelLiterals returns every string literal in the enclave's non-test
// Go source that is a Claude model ID, with a file that holds it. It reads
// the syntax tree, so comments do not count and build tags do not hide a
// file: the Bedrock map is found under every tag set.
func claudeModelLiterals(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	found := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == "third_party" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err == nil && claudeModelLiteral.MatchString(strings.ToLower(value)) {
				if _, seen := found[value]; !seen {
					found[value] = filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestEveryKnownClaudeModelHasAReasoningClass is the guard that keeps a new
// Claude model from falling onto the budget path unnoticed.
func TestEveryKnownClaudeModelHasAReasoningClass(t *testing.T) {
	found := claudeModelLiterals(t)
	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		want, listed := knownClaudeModelClasses[id]
		if !listed {
			got, _ := claudeReasoningClassOf(id)
			t.Errorf("%s (in %s) is a Claude model ID that knownClaudeModelClasses does not list. It would take the %q path today. "+
				"Find out which thinking and effort values the model accepts, add it to claudeReasoningModels in anthropic_reasoning.go "+
				"unless it is budget-only, and list it in this test with its class.", id, found[id], got)
			continue
		}
		if want == claudeAlias {
			continue
		}
		if got, claude := claudeReasoningClassOf(id); !claude || string(got) != want {
			t.Errorf("%s (in %s): reasoning class %q, want %q", id, found[id], got, want)
		}
	}
	// Every listed ID must still be in the source. This also proves the walk
	// reads the route tables: a walk that found nothing would fail here.
	for id := range knownClaudeModelClasses {
		if _, ok := found[id]; !ok {
			t.Errorf("%s is listed in knownClaudeModelClasses but is no longer in the non-test Go source: remove it from the list", id)
		}
	}
	for _, id := range []string{"anthropic/claude-haiku-5.5", "us.anthropic.claude-sonnet-5-5", "claude-opus-4-5-20251101", "anthropic/claude-fable-5.1"} {
		if _, ok := found[id]; !ok {
			t.Errorf("the source walk did not find %s, which a route table holds", id)
		}
	}
}

// The route tables themselves, walked in memory, agree with the list above.
func TestRouteTableClaudeModelsAreListed(t *testing.T) {
	for name, table := range map[string]map[string]string{"directModelMap": directModelMap, "gmiModelMap": gmiModelMap} {
		claudeRouteTableIsListed(t, name, table)
	}
}

func claudeRouteTableIsListed(t *testing.T, name string, table map[string]string) {
	t.Helper()
	seen := 0
	for catalog, upstream := range table {
		for _, id := range []string{catalog, upstream} {
			if !claudeModelLiteral.MatchString(strings.ToLower(id)) {
				continue
			}
			seen++
			want, listed := knownClaudeModelClasses[id]
			if !listed {
				t.Errorf("%s holds %s, which knownClaudeModelClasses does not list", name, id)
				continue
			}
			if got, _ := claudeReasoningClassOf(id); string(got) != want {
				t.Errorf("%s holds %s: reasoning class %q, want %q", name, id, got, want)
			}
		}
		// Both spellings of one model are one class.
		catalogClass, catalogClaude := claudeReasoningClassOf(catalog)
		upstreamClass, upstreamClaude := claudeReasoningClassOf(upstream)
		if catalogClaude && upstreamClaude && catalogClass != upstreamClass {
			t.Errorf("%s: %s is class %q but its upstream %s is class %q", name, catalog, catalogClass, upstream, upstreamClass)
		}
	}
	if seen == 0 {
		t.Errorf("%s holds no Claude model: the guard is not reading it", name)
	}
}
