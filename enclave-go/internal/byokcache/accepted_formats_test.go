package byokcache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"

	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// accepted_formats.json is the machine-readable answer to "which BYOK envelope
// formats does the enclave built from this commit ACCEPT?", and this test is
// the only thing allowed to write it.
//
// WHY A GENERATED DECLARATION AND NOT A PARSE
// -------------------------------------------
// quill-router's scripts/check_format_ordering.py refuses to deploy a control
// plane that writes a format the enclave serving its cloud cannot read. Its
// first version answered the question by parsing this package's source at the
// released commit and reading the case labels out of envelopeAAD's switch.
// A case label is not acceptance. Every one of these compiles, is gofmt-clean,
// reads like ordinary staged-rollout or hardening code, and keeps
// `case AlgorithmV2:` in the file while rejecting v2 at run time:
//
//  1. the case body returns an error behind a build/feature flag;
//  2. a kill switch ahead of the switch returns early for v2;
//  3. decryptEnvelope rejects the algorithm before it ever calls envelopeAAD;
//  4. the live dispatch is renamed and the old envelopeAAD is left as dead code.
//
// So the declaration is produced by BEHAVIOUR instead: for every algorithm
// constant this package declares, seal an envelope the way the control plane
// seals it and require (*Cache).Resolve — the same entry point settlement.go
// calls on the prompt path — to return the plaintext. A format is accepted iff
// a real round trip through the real entry point succeeds. All four evasions
// above turn into a failed round trip, so the regenerated declaration says V1
// and the deploy gate blocks.
//
// WHAT BINDS THE DECLARATION TO THE SOURCE
// ----------------------------------------
// source_sha256 pins every non-test .go file in this package. Editing any of
// them makes this test fail until it is re-run with -update-accepted-formats,
// which re-runs the probe. The consumer verifies those hashes against the same
// commit, so a stale declaration cannot describe a changed package.
//
// WHAT IT DOES NOT ESTABLISH
// --------------------------
//   - It is not a signature. Someone who edits this package, hand-edits both
//     `accepted` and `source_sha256`, and never runs CI produces a declaration
//     that the consumer accepts. The pin is that CI runs `go test ./...` on
//     every push and pull request, so the forgery has to survive a red build.
//   - It covers the byokcache read path only. A refusal upstream of this
//     package — settlement.go declining to hand a v2 envelope over at all —
//     is invisible here and would show as accepted.
//   - It says nothing about which build is RUNNING. That is the source_commit
//     assertion in the release record, and it is weaker than this.
const acceptedFormatsFile = "accepted_formats.json"

// probeControlAlgorithm must never be accepted. Without it a prober that
// somehow accepted everything (a broken seal, a decrypt that ignores AAD)
// would publish a declaration naming every candidate, and "accepts everything"
// is the one answer that makes the downstream gate useless.
const probeControlAlgorithm = "TR-BYOK-ENVELOPE-AES-256-GCM-PROBE-NOT-A-FORMAT"

const (
	probeWorkspace = "ws-probe"
	probeProvider  = "openai"
	probeSecret    = "probe-plaintext-not-a-credential" //nolint:gosec // fixture
)

var updateAcceptedFormats = flag.Bool(
	"update-accepted-formats",
	false,
	"rewrite accepted_formats.json from the behaviour this test observes",
)

// writerAAD is the CONTROL PLANE's side of each format, written out longhand
// rather than by calling aad/aadV2 from this package. Calling the package's own
// encoders would make the probe agree with the enclave by construction: a
// change to aadV2 would change both sides at once and the round trip would keep
// succeeding while every envelope the control plane actually wrote stopped
// opening. These bytes are quill-router's byok_crypto.py, transcribed.
var writerAAD = map[string]func(workspaceID, provider string) []byte{
	Algorithm: func(workspaceID, provider string) []byte {
		return []byte("trustedrouter:byok:" + workspaceID + ":" + provider)
	},
	AlgorithmV2: func(workspaceID, provider string) []byte {
		out := make([]byte, 0, 64)
		var length [4]byte
		for _, part := range []string{"trustedrouter/byok/v2", "provider", workspaceID, provider} {
			binary.BigEndian.PutUint32(length[:], uint32(len(part))) //nolint:gosec // fixture lengths
			out = append(out, length[:]...)
			out = append(out, part...)
		}
		return out
	},
}

type acceptedFormatsDeclaration struct {
	Schema          string            `json:"schema"`
	Package         string            `json:"package"`
	Accepted        []string          `json:"accepted"`
	RejectedControl string            `json:"rejected_control"`
	Probe           string            `json:"probe"`
	Generator       string            `json:"generator"`
	SourceSHA256    map[string]string `json:"source_sha256"`
}

const (
	declarationSchema  = "trustedrouter/byok-accepted-formats/v1"
	declarationPackage = "enclave-go/internal/byokcache"
	declarationProbe   = "seal an envelope with the control plane's own associated data, " +
		"then require (*Cache).Resolve to return the plaintext"
	declarationGenerator = "go test ./internal/byokcache -run TestAcceptedFormatsDeclaration " +
		"-args -update-accepted-formats"
)

var algorithmConstRE = regexp.MustCompile(`(?m)^\s*(Algorithm\w*)\s*=\s*"([^"]+)"`)

// declaredAlgorithms reads cache.go for the algorithm constants this package
// declares. Every one of them must be probed: a constant added without a probe
// is a format whose acceptance nobody measured, and the declaration would
// silently omit it.
func declaredAlgorithms(t *testing.T) map[string]string {
	t.Helper()
	source, err := os.ReadFile("cache.go")
	if err != nil {
		t.Fatalf("read cache.go: %v", err)
	}
	declared := map[string]string{}
	for _, match := range algorithmConstRE.FindAllStringSubmatch(string(source), -1) {
		declared[match[1]] = match[2]
	}
	if len(declared) == 0 {
		t.Fatal("cache.go declares no Algorithm* constant; this probe cannot enumerate formats")
	}
	return declared
}

// roundTrips is the whole definition of "accepted": seal, resolve, compare.
func roundTrips(t *testing.T, algorithm string, associated []byte) bool {
	t.Helper()
	block, err := aes.NewCipher(fixedDEK())
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := []byte("123456789012")
	envelope := EncryptedSecretEnvelope{
		Algorithm:    algorithm,
		KeyRef:       "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped-dek")),
		DEKNonce:     base64.URLEncoding.EncodeToString(nonce),
		Ciphertext: base64.URLEncoding.EncodeToString(
			gcm.Seal(nil, nonce, []byte(probeSecret), associated),
		),
		Nonce: base64.URLEncoding.EncodeToString(nonce),
	}
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})
	secret, _, err := cache.Resolve(t.Context(), probeWorkspace, probeProvider, "", envelope)
	if err != nil {
		return false
	}
	if secret != probeSecret {
		t.Fatalf("%s resolved to %q, not the sealed plaintext", algorithm, secret)
	}
	return true
}

func observedAccepted(t *testing.T) []string {
	t.Helper()
	accepted := []string{}
	for name, algorithm := range declaredAlgorithms(t) {
		seal, ok := writerAAD[algorithm]
		if !ok {
			t.Fatalf(
				"cache.go declares %s = %q and this probe does not know how the control plane "+
					"seals it. Add its associated data to writerAAD -- an unprobed format cannot "+
					"be declared accepted, and guessing is how the gate this feeds goes green on "+
					"an outage.",
				name, algorithm,
			)
		}
		if roundTrips(t, algorithm, seal(probeWorkspace, probeProvider)) {
			accepted = append(accepted, algorithm)
		}
	}
	sort.Strings(accepted)
	return accepted
}

func sourceHashes(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	hashes := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sum := sha256.Sum256(body)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	if len(hashes) == 0 {
		t.Fatal("no non-test .go files found; the declaration would pin nothing")
	}
	return hashes
}

func TestAcceptedFormatsDeclarationMatchesBehaviour(t *testing.T) {
	accepted := observedAccepted(t)
	if len(accepted) == 0 {
		t.Fatal("no declared algorithm round-trips; either this build reads nothing or the probe is broken")
	}
	if roundTrips(t, probeControlAlgorithm, writerAAD[AlgorithmV2](probeWorkspace, probeProvider)) {
		t.Fatalf(
			"the control algorithm %q round-tripped. This probe cannot tell an accepted format "+
				"from a rejected one, so nothing it declares means anything.",
			probeControlAlgorithm,
		)
	}

	want := acceptedFormatsDeclaration{
		Schema:          declarationSchema,
		Package:         declarationPackage,
		Accepted:        accepted,
		RejectedControl: probeControlAlgorithm,
		Probe:           declarationProbe,
		Generator:       declarationGenerator,
		SourceSHA256:    sourceHashes(t),
	}
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("encode declaration: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateAcceptedFormats {
		if err := os.WriteFile(acceptedFormatsFile, encoded, 0o600); err != nil {
			t.Fatalf("write %s: %v", acceptedFormatsFile, err)
		}
		t.Logf("wrote %s: accepts %s", acceptedFormatsFile, strings.Join(accepted, ", "))
		return
	}

	onDisk, err := os.ReadFile(acceptedFormatsFile)
	if err != nil {
		t.Fatalf(
			"%s is missing (%v). It is the only evidence the deploy gate has about what this "+
				"build reads. Regenerate with:\n  %s",
			acceptedFormatsFile, err, declarationGenerator,
		)
	}
	if string(onDisk) != string(encoded) {
		t.Fatalf(
			"%s no longer describes this package.\n\non disk:\n%s\nobserved:\n%s\n"+
				"Regenerate with:\n  %s\n\nIf `accepted` shrinks, a format this enclave used to "+
				"read no longer opens, and every control plane writing it is about to break.",
			acceptedFormatsFile, onDisk, encoded, declarationGenerator,
		)
	}
}

// The declaration is worth nothing if the probe cannot see a rejection, so the
// rejection is fabricated here rather than trusted: a build whose envelopeAAD
// refuses v2 must produce an accepted set without v2. This drives the same
// round-trip helper the declaration is generated from.
func TestProbeSeesARejectedFormat(t *testing.T) {
	if roundTrips(t, AlgorithmV2, writerAAD[Algorithm](probeWorkspace, probeProvider)) {
		t.Fatal("a v2 envelope sealed under v1 associated data must not open")
	}
	if !roundTrips(t, AlgorithmV2, writerAAD[AlgorithmV2](probeWorkspace, probeProvider)) {
		t.Fatal("a correctly sealed v2 envelope must open; the probe is broken")
	}
}

// A case label with no working body is the whole point of generating this
// declaration rather than parsing it, so the equivalence is asserted here:
// `case AlgorithmV2:` is present in cache.go AND the control algorithm — which
// has no case label — does not resolve. What the probe reads is Resolve's
// result. Rejecting inside the case body, guarding ahead of the switch,
// rejecting in the caller, and renaming the dispatch all reach it as the same
// thing: an error instead of a plaintext.
func TestProbeReadsResolveNotSyntax(t *testing.T) {
	source, err := os.ReadFile("cache.go")
	if err != nil {
		t.Fatalf("read cache.go: %v", err)
	}
	if !strings.Contains(string(source), "case AlgorithmV2:") {
		t.Skip("cache.go no longer has a v2 case label; this assertion has nothing to contrast")
	}
	if roundTrips(t, probeControlAlgorithm, writerAAD[AlgorithmV2](probeWorkspace, probeProvider)) {
		t.Fatal("an algorithm with no case label must not resolve")
	}
}
