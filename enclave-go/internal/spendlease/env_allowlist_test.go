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
	readPattern := regexp.MustCompile(`os\.Getenv\("((?:QUILL_)?SPEND_LEASE[A-Z0-9_]*)"\)`)
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

func TestStageCLocalAdmissionDeployFlagIsOptInAndAbsentFromWorkflows(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	enclaveRoot := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	worktreeRoot := filepath.Dir(enclaveRoot)
	deploy, err := os.ReadFile(filepath.Join(worktreeRoot, "tools", "deploy-gcp-mig.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(deploy)
	for _, required := range []string{
		`SPEND_LEASE_LOCAL_ADMISSION="${SPEND_LEASE_LOCAL_ADMISSION:-off}"`,
		`if [ "${SPEND_LEASE_LOCAL_ADMISSION}" = "on" ]; then`,
		`|tee-env-SPEND_LEASE_LOCAL_ADMISSION=${SPEND_LEASE_LOCAL_ADMISSION}`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("deploy script is missing Stage C opt-in fragment %q", required)
		}
	}
	workflowRoot := filepath.Join(worktreeRoot, ".github", "workflows")
	err = filepath.WalkDir(workflowRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(body), "SPEND_LEASE_LOCAL_ADMISSION") {
			t.Errorf("Stage C enclave flag must not be enabled or mentioned by workflow %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
