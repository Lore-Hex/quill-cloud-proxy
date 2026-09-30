//go:build ignore

// Run from enclave-go/internal/speculation: go run ./testdata/mutate.go
// All builds and edits occur in temporary copies; no git commands are used.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type mutation struct {
	Name, File, Function, Before, After, Literal string
	RouterRules                                  []int `json:"router_rules"`
}
type result struct {
	Mutation mutation
	Status   string
	Failures []string
	Selected bool
	Output   string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func copyPackage(source, destination string) {
	must(filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(destination, rel), 0700)
		}
		// Copy only source, pinned data and executable inventory; never report output.
		if filepath.Ext(path) != ".go" && filepath.Ext(path) != ".json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destination, rel), b, 0600)
	}))
	// The package has only standard-library dependencies. This isolated module
	// prevents tests or Go tooling from writing into the user's worktree.
	must(os.WriteFile(filepath.Join(destination, "go.mod"), []byte("module speculation-mutation\n\ngo 1.24\n"), 0600))
}
func apply(dir string, m mutation) {
	path := filepath.Join(dir, m.File)
	b, err := os.ReadFile(path)
	must(err)
	source := string(b)
	start, end := 0, len(source)
	if m.Function != "" {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, b, 0)
		must(err)
		found := false
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == m.Function {
				start = fset.Position(fn.Pos()).Offset
				end = fset.Position(fn.End()).Offset
				found = true
				break
			}
		}
		if !found {
			panic("missing mutation function " + m.Function)
		}
	}
	scope := source[start:end]
	if strings.Count(scope, m.Before) != 1 {
		panic("mutation anchor not unique: " + m.Name)
	}
	source = source[:start] + strings.Replace(scope, m.Before, m.After, 1) + source[end:]
	must(os.WriteFile(path, []byte(source), 0600))
}
func run(dir string, m mutation) result {
	cmd := exec.Command("go", "test", "-json", "-count=1", "-run", "^Test(FixturePins|Literals|Verdicts)$", ".")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	r := result{Mutation: m, Status: "survived", Output: string(output)}
	if err == nil {
		return r
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(output, []byte("\n")) {
		var event struct{ Action, Test string }
		if json.Unmarshal(line, &event) == nil && event.Action == "fail" && event.Test != "" {
			seen[event.Test] = true
		}
	}
	for name := range seen {
		r.Failures = append(r.Failures, name)
	}
	sort.Strings(r.Failures)
	r.Selected = seen[m.Literal]
	if len(r.Failures) > 0 {
		r.Status = "red"
	} else {
		r.Status = "build-broken"
	}
	return r
}
func main() {
	source, err := os.Getwd()
	must(err)
	raw, err := os.ReadFile("mutations.json")
	must(err)
	var inventory struct{ Mutations []mutation }
	must(json.Unmarshal(raw, &inventory))
	temp, err := os.MkdirTemp("", "speculation-mutations-")
	must(err)
	defer os.RemoveAll(temp)
	baseline := filepath.Join(temp, "baseline")
	copyPackage(source, baseline)
	b := run(baseline, mutation{Name: "baseline"})
	if b.Status != "survived" {
		panic("baseline failed:\n" + b.Output)
	}
	fmt.Println("Baseline: all pinned literals pass")
	results := make([]result, len(inventory.Mutations))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				m := inventory.Mutations[i]
				dir := filepath.Join(temp, fmt.Sprint(i))
				copyPackage(source, dir)
				apply(dir, m)
				r := run(dir, m)
				results[i] = r
				must(os.RemoveAll(dir))
				fmt.Printf("%03d %s selected=%v %s\n", i, r.Status, r.Selected, m.Name)
			}
		}()
	}
	for i := range inventory.Mutations {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	var report strings.Builder
	report.WriteString("# Go speculation mutation results\n\nEvery mutant ran the full 434 protocol + 24 verdict corpus and fixture pins in a temporary copy. Baseline passed. No git commands were used. `Selected` indicates whether the inventory's named literal failed.\n\n| Mutation | Result | Selected | Failing test |\n|---|---|---|---|\n")
	counts := map[string]int{}
	missing := 0
	for _, r := range results {
		counts[r.Status]++
		if !r.Selected {
			missing++
		}
		failure := "—"
		if len(r.Failures) > 0 {
			failure = strings.Join(r.Failures, ", ")
		}
		if r.Selected {
			failure = r.Mutation.Literal
		}
		fmt.Fprintf(&report, "| %s | %s | %t | %s |\n", r.Mutation.Name, r.Status, r.Selected, failure)
	}
	fmt.Fprintf(&report, "\nRed: %d; survived: %d; build-broken: %d; selected literal not red: %d.\n", counts["red"], counts["survived"], counts["build-broken"], missing)
	must(os.WriteFile("mutation-report.md", []byte(report.String()), 0600))
	data, err := json.MarshalIndent(results, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(os.TempDir(), "speculation-mutation-results.json"), data, 0600))
	fmt.Print(report.String()[strings.LastIndex(report.String(), "\nRed:"):])
	if counts["survived"]+counts["build-broken"]+missing > 0 {
		os.Exit(1)
	}
}
