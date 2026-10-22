// Reproduce the pinned Rekor subset without changing offline proof verification.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const upstream = "github.com/sigstore/rekor@v1.5.0"
const checksum = "h1:rL7SghHd5HLCtsCrxw0yQg+NczGvM75EjSPPWuGjaiQ="

var packages = []string{
	"generated/models", "internal/log", "pki/identity", "pki/pkitypes",
	"types", "pki/x509", "types/dsse", "types/dsse/v0.0.1",
	"types/hashedrekord", "util", "types/hashedrekord/v0.0.1",
	"types/intoto", "types/intoto/v0.0.2", "verify",
	// Sigstore's unchanged verification tests also construct signed entries.
	// These HTTP packages stay test-only; the runtime binary gate enforces it.
	"generated/client", "generated/client/entries", "generated/client/index",
	"generated/client/pubkey", "generated/client/tlog", "client", "pki",
	"pki/minisign", "pki/pgp", "pki/pkcs7", "pki/ssh", "pki/tuf",
	"tle", "types/rekord",
}

func main() {
	check := flag.Bool("check", false, "compare the checked-in subset with pinned upstream")
	dest := flag.String("dest", "third_party/rekor-offline", "output directory relative to enclave-go")
	flag.Parse()
	data, err := exec.Command("go", "mod", "download", "-json", upstream).Output()
	must(err)
	var mod struct{ Dir, Sum string }
	must(json.Unmarshal(data, &mod))
	if mod.Dir == "" || mod.Sum != checksum {
		panic("unexpected Rekor module checksum")
	}
	files := map[string][]byte{}
	for _, name := range []string{"LICENSE"} {
		files[name], err = os.ReadFile(filepath.Join(mod.Dir, name))
		must(err)
	}
	for _, pkg := range packages {
		dir := filepath.Join("pkg", pkg)
		entries, err := os.ReadDir(filepath.Join(mod.Dir, dir))
		must(err)
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || strings.HasSuffix(name, "_test.go") ||
				(!strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".json")) {
				continue
			}
			path := filepath.Join(dir, name)
			files[path], err = os.ReadFile(filepath.Join(mod.Dir, path))
			must(err)
		}
	}
	files["pkg/verify/verify.go"] = offline(files["pkg/verify/verify.go"], false)
	tests, err := os.ReadFile(filepath.Join(mod.Dir, "pkg/verify/verify_test.go"))
	must(err)
	files["pkg/verify/verify_test.go"] = offline(tests, true)
	if *check {
		must(filepath.WalkDir(*dest, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			rel, err := filepath.Rel(*dest, path)
			if err != nil {
				return err
			}
			if rel != "README.md" && rel != "go.mod" && rel != "go.sum" && files[rel] == nil {
				return fmt.Errorf("unreviewed vendored file: %s", rel)
			}
			return nil
		}))
	}
	for path, want := range files {
		target := filepath.Join(*dest, path)
		if *check {
			got, err := os.ReadFile(target)
			must(err)
			if !bytes.Equal(got, want) {
				panic("upstream drift: " + path)
			}
		} else {
			must(os.MkdirAll(filepath.Dir(target), 0755))
			must(os.WriteFile(target, want, 0600))
		}
	}
	fmt.Printf("Verified %d Rekor files from %s (%s); only unused online declarations omitted\n", len(files), upstream, checksum)
}

func offline(source []byte, tests bool) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "verify.go", source, parser.ParseComments)
	must(err)
	names := map[string]bool{"ProveConsistency": true, "VerifyCurrentCheckpoint": true}
	imports := map[string]bool{
		"github.com/sigstore/rekor/pkg/generated/client":      true,
		"github.com/sigstore/rekor/pkg/generated/client/tlog": true,
	}
	expected := 2
	if tests {
		names = map[string]bool{"TestConsistency": true, "GetLogProof": true, "GetLogInfo": true, "SetTransport": true, "TlogClient": true}
		imports["github.com/go-openapi/runtime"] = true
		expected = 5
	}
	var decls []ast.Decl
	var spans [][2]token.Pos
	removed := 0
	for _, d := range f.Decls {
		remove := false
		switch node := d.(type) {
		case *ast.FuncDecl:
			remove = names[node.Name.Name]
		case *ast.GenDecl:
			if node.Tok == token.TYPE && len(node.Specs) == 1 {
				remove = names[node.Specs[0].(*ast.TypeSpec).Name.Name]
			}
			if node.Tok == token.IMPORT {
				var specs []ast.Spec
				for _, spec := range node.Specs {
					path, err := strconv.Unquote(spec.(*ast.ImportSpec).Path.Value)
					must(err)
					if !imports[path] {
						specs = append(specs, spec)
					}
				}
				node.Specs = specs
			}
		}
		if remove {
			start := d.Pos()
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Doc != nil {
				start = fn.Doc.Pos()
			}
			spans = append(spans, [2]token.Pos{start, d.End()})
			removed++
		} else {
			decls = append(decls, d)
		}
	}
	if removed != expected {
		panic("upstream declaration set changed")
	}
	f.Decls = decls
	var comments []*ast.CommentGroup
	for _, comment := range f.Comments {
		keep := true
		for _, span := range spans {
			if comment.Pos() >= span[0] && comment.End() <= span[1] {
				keep = false
			}
		}
		if keep {
			comments = append(comments, comment)
		}
	}
	f.Comments = comments
	var buf bytes.Buffer
	must(format.Node(&buf, fset, f))
	return buf.Bytes()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
