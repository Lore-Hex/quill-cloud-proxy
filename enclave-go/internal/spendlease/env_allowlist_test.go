package spendlease

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestSpendLeaseEnvReadsAreInGCPMultiLaunchPolicy(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	enclaveRoot := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	dockerfile, err := os.ReadFile(filepath.Join(enclaveRoot, "Dockerfile.enclave.gcp.multi"))
	if err != nil {
		t.Fatal(err)
	}
	readPattern := regexp.MustCompile(`os\.Getenv\("(QUILL_SPEND_LEASE[A-Z0-9_]*)"\)`)
	seen := map[string]bool{}
	err = filepath.WalkDir(enclaveRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.Contains(path, string(filepath.Separator)+"third_party"+string(filepath.Separator)) {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, match := range readPattern.FindAllSubmatch(content, -1) {
			seen[string(match[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("no QUILL_SPEND_LEASE env reads found; coverage test is vacuous")
	}
	label := string(dockerfile)
	for name := range seen {
		if !strings.Contains(label, name) {
			t.Errorf("%s is read by enclave source but absent from allow_env_override", name)
		}
	}
}
