package speculation

import (
	"encoding/base64"
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNoProductionImports(t *testing.T) {
	root := filepath.Clean("../..")
	self := filepath.Join(root, "internal", "speculation")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == self {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasSuffix(name, "/internal/speculation") {
				t.Errorf("production import: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCallerValues(t *testing.T) {
	h := newHarness(t)
	for i, value := range []any{nil, true, "1", 1.0, json.Number("1"), []any{}, map[string]any{}} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if _, err := CostCeiling(value, 0, 0, 0, 0); err != ProtocolError("integer") {
				t.Fatalf("cost: %v", err)
			}
			if _, err := WorkspaceAllowance(0, value); err != ProtocolError("integer") {
				t.Fatalf("allowance: %v", err)
			}
		})
	}
	if n, err := CostCeiling(1, 1, 1, 1, 0); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	auth := map[string]any{"extra": cycle}
	if _, err := VerifyAcceptance(map[string]any{"authorization": auth}, h.descriptor, auth); err != ProtocolError("authorization") {
		t.Fatal("cyclic caller data", err)
	}
	if _, err := VerifyGrant(h.real.Compact(), h.keys, nil, 1700000000, false); err != ProtocolError("binding") {
		t.Fatal("nil context", err)
	}
	if _, err := (VerifiedGrant{}).Claims(); err == nil {
		t.Fatal("zero grant claims")
	}
	if _, err := (VerifiedDescriptor{}).Claims(); err == nil {
		t.Fatal("zero descriptor claims")
	}
	for size := 0; size <= 70; size++ {
		k := append([]TrustedKey(nil), h.keys...)
		for i := range k {
			if k[i].Purpose == "grant" {
				k[i].PublicKeyB64URL = base64.RawURLEncoding.EncodeToString(make([]byte, size))
			}
		}
		if _, err := VerifyGrant(h.real.Compact(), k, m(h.bundle["context"]), h.bundle["now"], false); err != ProtocolError("signature") {
			t.Fatalf("key length %d: %v", size, err)
		}
	}
}

func TestParserWholeSyntax(t *testing.T) {
	// These independently authored checks cover adjacency around the constant
	// tokenizer, which must never turn malformed text into a legal number.
	for _, raw := range []string{"1NaN", "-NaN", "NaN0", "Infinity1", "1Infinity", "-Infinity0", "[NaN 1]", "{\"a\":NaN,}", "{\"a\":1,\"a\":NaN} trailing"} {
		t.Run(raw, func(t *testing.T) {
			var err error
			func() { defer refusal(&err); parseJSON([]byte(raw)) }()
			if err != ProtocolError("json") {
				t.Fatalf("expected json, got %v", err)
			}
		})
	}
}

func TestConcurrentClaims(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 16; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			claims, err := h.real.Claims()
			if err != nil {
				t.Fatal(err)
			}
			claims["route"].(map[string]any)["endpoint_id"] = "modified"
			next, err := h.real.Claims()
			if err != nil || next["route"].(map[string]any)["endpoint_id"] == "modified" {
				t.Fatal("claims alias", err)
			}
			if v, err := RenewalVerdict(h.real, h.real); err != nil || v != "replay" {
				t.Fatal(v, err)
			}
		})
	}
}

func TestMutationInventory(t *testing.T) {
	raw, err := os.ReadFile("mutations.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Mutations []struct {
			Name, File, Function, Before, After, Literal string
			RouterRules                                  []int `json:"router_rules"`
		}
	}
	if err = json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{"TestFixturePins": true, "TestEqualSharedDAG": true}
	for _, name := range []string{"unsupported", "map_cycle", "slice_cycle", "slice_views", "map_right_identity", "slice_right_identity"} {
		cases["TestEqualValues/"+name] = true
	}
	for _, v := range loadFixture(t, "protocol-vectors.json")["cases"].([]any) {
		cases["TestLiterals/"+s(m(v)["name"])] = true
	}
	for _, v := range loadFixture(t, "verdict-vectors.json")["vectors"].([]any) {
		cases["TestVerdicts/"+s(m(v)["name"])] = true
	}
	rules := loadFixture(t, "rules.json")["rules"].([]any)
	names := map[string]bool{}
	for _, entry := range inventory.Mutations {
		if names[entry.Name] || !cases[entry.Literal] || entry.Before == entry.After {
			t.Errorf("invalid inventory entry %s", entry.Name)
		}
		names[entry.Name] = true
		for _, i := range entry.RouterRules {
			if i < 0 || i >= len(rules) {
				t.Errorf("invalid router rule index %d", i)
			}
		}
	}
}
