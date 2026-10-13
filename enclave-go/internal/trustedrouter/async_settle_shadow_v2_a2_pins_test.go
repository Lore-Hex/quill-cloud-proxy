package trustedrouter

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The router's combined contract fixture release for revisions a1 and a2, copied byte for byte. The
// enclave's behaviour does not change with it: nothing outside this test reads these files. The pins are
// independent of the release's own manifests so a regenerated release cannot move both sides at once.
const shadowV2A2ManifestSHA256 = "ae3835553ddacc18a12eb5206f355cff92732b8a401cdc2a74a2afa13697cc78"
const shadowV2A1ManifestSHA256 = "df704c8d597c2118c487edb6cdb84f6600f20356054e9c6c59edbd196b2aa6db"

var shadowV2A2Pins = map[string]string{
	"a1/authorization_obligations.json":   "cf513d39d2683a8cf4086d7fa1e73e12029861eabd16d746472548364bccd701",
	"a1/authorize_compared.json":          "f405ada111b96a50f9f548f2dee415f609bf81cd914de182cdf7f11e14574e94",
	"a1/authorize_excluded.json":          "70392c30c884c9c6231fc72d7a28d3971e018295276c79d9d83c003f827a0045",
	"a1/capability_headers.json":          "b8321f95f86c6fa29b92e8c7286bdf69b0a505b5fac02b437f172f02aff094d2",
	"a1/certificate_record.json":          "afa80d6fa9b9c4c2585b43888ef2338fbada2e561bbe863b0d10cbcf1873b6cd",
	"a1/close_result.json":                "6c0db43669dad1a2c158fbbf796bc8e7acea5607b212a0f5ea08e1b66de57212",
	"a1/closure.json":                     "8531e7f6caf1b095520fbe2cfd7ebcb9d9bb8940dd68aa4222c2d9c1e35d6f69",
	"a1/completion_context.json":          "5e8a75def45439aebd01e4c24e059a8ad2df92ecaf89c61e2047160c0bb54282",
	"a1/controls.json":                    "429f9d9928366f3c327a7b0b1f3707c5c73523a737e2b0a59f618260bc816b75",
	"a1/counter.json":                     "8b61bc51c6882cd4827c2c99f9f8c8df3429ee3c39c0bdf06a939d2101518377",
	"a1/exclusion_certificate.json":       "1ac66af1d68255374f41f234463bbede61f294dbe53cacd0fb284d8e8478cb64",
	"a1/gate_outputs.json":                "4b90fb664d3f79283ba30013da68919424a077368a5039723bde0aa09046f3eb",
	"a1/handoff_accounting.json":          "f1d985100020a05b7307b1b8b86a2c4d577a0fd50bdff38d93a4400b38b5572d",
	"a1/health.json":                      "8168a99b83ce5dd964c93e2406fe899b27fa2f9e3a686938b2348478172406d4",
	"a1/health_basis.json":                "074e53eb40a609796114f45f4e411862b0a454652696ccb6cbbe862c100000d4",
	"a1/health_claim.json":                "38de1b648b9c0e84645ad0c16320909793cab3c1a26a889bd8b776b018ceccf5",
	"a1/health_read_metadata.json":        "04747765973bc58d29b74d24f3c9fb55286e054f054dd76804e58083926a600f",
	"a1/manifest.json":                    "df704c8d597c2118c487edb6cdb84f6600f20356054e9c6c59edbd196b2aa6db",
	"a1/prerequisite_ledger.json":         "0f9803dc394d12de5db166b92470d1d2fd4ccd8c138acbcd48cee66010fb84a8",
	"a1/proof_manifest.json":              "765bf998f4e103d9f9f0d6c3e34bed1a1f745af8105f64185861561e6a9f2286",
	"a1/publisher_slot_trace.json":        "80a7264a9bd5f92da2b4a46bbeb9208da11ec844c6adcd4563a263a42a61193c",
	"a1/purpose_rejections.json":          "15b745b177744fedcaed659ac41abbf05aad7b9fc75705d85bb6f81cd7ac86b7",
	"a1/receipt_pages.json":               "e9f83ebb045d22c3d127bd52ecebefe919ea994ef7af21d885e28a934842e84d",
	"a1/sample.json":                      "b3af8a27de86863035f84ec790945a6d2efcbbcfc56dfff95917e2d7fffda759",
	"a1/terminal_compared_failure.json":   "a33e7f30d6501bfae2ebb08bdc713e459e7bc0ebb2d553fd3933c3f85a158043",
	"a1/terminal_compared_full.json":      "d5e6fcfd096da7eb7820af10f38983f6d7661cce94abef902acaff9f3e64488c",
	"a1/terminal_compared_hash_only.json": "7c41c282cae00eee2919f13322c35c7a073dc6240a35a4ffcf423ecf16da7fae",
	"a1/terminal_excluded_refund.json":    "3694f06b9b72e9e45dadc70148df372fe3c8067c35f7e1fe3ff78fbd1e7e2554",
	"a1/terminal_excluded_settle.json":    "698789fb3742739eab40eaf117a10b85cf66cb946144323887a035fb4e4fa491",
	"a1/wire_rejections.json":             "fac4e0550164aaa315344bb6f4e66ef2509ee13e037463098a0526ee74db6771",
	"budget_envelopes.json":               "a8f597cf23b95664c3890dc389ca81dd1ba642ae6cdb6103d0915aa73167b802",
	"cohort_seed_policy.json":             "2c82368a9c5ff8de0338008be3bc2f39303fa9c6ca2afa80d2ef5f333efeee84",
	"delegated_payloads.json":             "e7ca59ed29964e4c2df034259ea8b40a883b6164123dc06d767f08632edc40a4",
	"external_proofs.json":                "670292bb9b25900ac7259bd0e0def8853ab63b64e2eded885de70ac0fbcc3919",
	"failure_pages.json":                  "a7ad5e6f713b12f31b7725a01afbdcbdd01cf764779d3d42bb8c9c4457bafc8f",
	"gate_failures.json":                  "8a7bedf32cd495a1d46804a6567ed79c144ad3fd908f7051bd778792e873614e",
	"gate_outputs_a2.json":                "466effa391670c0ee8f11c3d4c659d5e8385cdc86297a26480c3a22618c5350a",
	"gate_report.json":                    "75b776273bccc165a3ea405dbcdddce8fd0fb9b3325c7bed2b03cd778ce5706b",
	"independent_inventory.json":          "330e84a2d15f7de429cdb7301245bdead6d66420fc5b2406b50bb59193619a1d",
	"input_inventory.json":                "088631d982b7f47d0a7d7d590e5b9e6de6fb596f24391fa259239de0155fa9e0",
	"manifest.json":                       "ae3835553ddacc18a12eb5206f355cff92732b8a401cdc2a74a2afa13697cc78",
	"region_reports.json":                 "afbc7170c91893f85cc29a305a12bdbbc8ac73944b27dbe37f85d67936e9bef0",
	"resolution_dag.json":                 "0fadc3427349a721b38f846fb21290d64e7a48e269eee8ac2afbb44fb0be6747",
	"root_preimages.json":                 "35f4f52281f19a84d15905f5a4ccdcb9559c3eea34854eb1c653b727d0ff951a",
	"shutdown_inventory.json":             "103d872b3c3b8b0651636afe27b90c3e07f8d72a57e22318b9c04e076a1984c1",
	"verifier_ports.json":                 "55d0ac7f874ca14034ff54b9dd95fcbe7aaa3ad3c207a42ebe277c8bbe85b301",
	"writer_reports.json":                 "a87787092b29f35967a277c791ddccd65401f2e9fe154cf144552a2a11996a7c",
}

type shadowV2ReleaseEntry struct {
	SHA        string            `json:"sha256"`
	Variants   []string          `json:"variants"`
	VariantSHA map[string]string `json:"variant_sha256"`
}

type shadowV2ReleaseManifest struct {
	V        int                             `json:"v"`
	Policy   string                          `json:"policy_version"`
	Revision string                          `json:"contract_revision"`
	Baseline string                          `json:"baseline_manifest_sha256"`
	SourceA1 string                          `json:"source_a1_manifest_sha256"`
	Files    map[string]shadowV2ReleaseEntry `json:"files"`
}

func TestShadowV2A2FixturePins(t *testing.T) {
	root := filepath.Join("testdata", "async_settlement", "shadow_v2_a2")
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		want, ok := shadowV2A2Pins[name]
		if !ok || fmt.Sprintf("%x", sha256.Sum256(raw)) != want {
			t.Fatal(name)
		}
		if !bytes.HasSuffix(raw, []byte("\n")) || bytes.HasSuffix(raw, []byte("\n\n")) {
			t.Fatal(name)
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 47 || len(shadowV2A2Pins) != 47 {
		t.Fatal("fixture inventory")
	}
	if shadowV2A2Pins["manifest.json"] != shadowV2A2ManifestSHA256 || shadowV2A2Pins["a1/manifest.json"] != shadowV2A1ManifestSHA256 {
		t.Fatal("manifest pins")
	}
	base, err := os.ReadFile(filepath.Join("testdata", "async_settlement", "shadow_v2", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := fmt.Sprintf("%x", sha256.Sum256(base))
	read := func(name string) shadowV2ReleaseManifest {
		var m shadowV2ReleaseManifest
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || json.Unmarshal(raw, &m) != nil {
			t.Fatal(name)
		}
		if m.V != 2 || m.Policy != "shadow-v2" || m.Baseline != baseline {
			t.Fatal(name + " identity")
		}
		return m
	}
	manifest, inner := read("manifest.json"), read("a1/manifest.json")
	if manifest.Revision != "a2" || manifest.SourceA1 != shadowV2A1ManifestSHA256 || len(manifest.Files) != 46 {
		t.Fatal("a2 manifest identity")
	}
	if inner.Revision != "a1" || inner.SourceA1 != "" || len(inner.Files) != 29 {
		t.Fatal("a1 manifest identity")
	}
	for name, entry := range inner.Files {
		if !reflect.DeepEqual(manifest.Files["a1/"+name], entry) {
			t.Fatal("a1/" + name)
		}
	}
	for name, entry := range manifest.Files {
		if shadowV2A2Pins[name] != entry.SHA {
			t.Fatal(name)
		}
		if name == "a1/manifest.json" {
			if len(entry.Variants) != 0 || len(entry.VariantSHA) != 0 {
				t.Fatal(name)
			}
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			V        int               `json:"v"`
			Policy   string            `json:"policy_version"`
			Revision string            `json:"contract_revision"`
			Variants []json.RawMessage `json:"variants"`
		}
		if json.Unmarshal(body, &file) != nil || file.V != 2 || file.Policy != "shadow-v2" {
			t.Fatal(name)
		}
		// Under a1/, a file the first amendment leaves alone is the baseline's bytes and carries no
		// revision, and every other file says a1. Every file the second amendment adds says a2.
		want := "a2"
		if short, ok := strings.CutPrefix(name, "a1/"); ok {
			want = "a1"
			if shadowV2Pins[short] == shadowV2A2Pins[name] {
				want = ""
			}
		}
		if file.Revision != want {
			t.Fatal(name + " revision")
		}
		var names []string
		for _, v := range file.Variants {
			var head struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(v, &head) != nil || head.Name == "" {
				t.Fatal(name)
			}
			if fmt.Sprintf("%x", sha256.Sum256(v)) != entry.VariantSHA[head.Name] {
				t.Fatal(name + "/" + head.Name)
			}
			names = append(names, head.Name)
		}
		if len(names) == 0 || !reflect.DeepEqual(names, entry.Variants) || len(entry.VariantSHA) != len(names) {
			t.Fatal(name)
		}
	}
}
