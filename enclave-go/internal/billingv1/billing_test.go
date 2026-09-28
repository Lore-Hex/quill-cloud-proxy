package billingv1

import (
	"bytes"
	"encoding/json"
	"math"
	"sync"
	"testing"
)

func fixtureNamed(t *testing.T, name string) fixtureCase {
	t.Helper()
	for _, c := range loadFixture(t).Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatal("missing fixture", name)
	return fixtureCase{}
}
func TestSnapshotImmutability(t *testing.T) {
	c := fixtureNamed(t, "tier_last_fallback")
	source := append([]byte{}, c.Snapshot...)
	s, err := ParseSnapshot(source)
	if err != nil {
		t.Fatal(err)
	}
	before, err := CanonicalBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	for i := range source {
		source[i] = 'x'
	}
	copyOfSnapshot := s
	candidates := copyOfSnapshot.Candidates()
	candidates[0].EndpointID = "changed"
	candidates[0].Rates.InputMicroPerMillion = 999
	candidates[0].Tiers[0].Rates.InputMicroPerMillion = 999
	*candidates[0].Tiers[0].MaxPromptTokens = 999
	candidates = append(candidates, Candidate{})
	candidates[0].Tiers = append(candidates[0].Tiers, Tier{})
	before[0] = 'x'
	after, err := CanonicalBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	parsedAgain, err := ParseSnapshot(c.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	original, err := CanonicalBytes(parsedAgain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("caller mutated frozen snapshot")
	}
	raw, err := ParseRawUsage(c.RawUsage)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Evaluate(s, c.SelectedEndpoint, raw, DefaultEligibility())
	if err != nil || result.ChargeMicro != *c.ExpectedChargeMicro {
		t.Fatalf("changed charge: %+v %v", result, err)
	}
}
func TestBuilderCopiesAndSorts(t *testing.T) {
	first, err := fixtureEndpoints(fixtureNamed(t, "openai_cache").Snapshot, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixtureEndpoints(fixtureNamed(t, "anthropic_cache").Snapshot, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := append(first, second...)
	snapshot, err := BuildSnapshot(endpoints, DefaultEligibility())
	if err != nil {
		t.Fatal(err)
	}
	before, err := CanonicalBytes(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	endpoints[0].ID = "changed"
	endpoints[0].Tiers[0].InputMicroPerMillion = 999
	*endpoints[0].Tiers[0].CachedInputMicroPerMillion = 999
	endpoints = nil
	after, err := CanonicalBytes(snapshot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("builder retained caller data")
	}
	candidates := snapshot.Candidates()
	if candidates[0].EndpointID >= candidates[1].EndpointID {
		t.Fatal("not sorted")
	}
	for _, input := range [][]Endpoint{nil, {second[0], second[0]}} {
		if _, err = BuildSnapshot(input, DefaultEligibility()); err == nil {
			t.Fatal("accepted empty/duplicate endpoints")
		}
	}
}
func TestConcurrentEvaluation(t *testing.T) {
	c := fixtureNamed(t, "fallback_winner")
	s, err := ParseSnapshot(c.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ParseRawUsage(c.RawUsage)
	if err != nil {
		t.Fatal(err)
	}
	expectedHash, err := CanonicalHash(s)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 50; j++ {
				result, err := Evaluate(s, c.SelectedEndpoint, raw, DefaultEligibility())
				if err != nil || result.ChargeMicro != *c.ExpectedChargeMicro || result.Usage != *c.ExpectedNormalizedUsage {
					t.Errorf("evaluation changed: %+v %v", result, err)
					return
				}
				hash, err := CanonicalHash(s)
				if err != nil || hash != expectedHash {
					t.Errorf("hash changed: %s %v", hash, err)
					return
				}
				detached := s.Candidates()
				detached[0].Rates.InputMicroPerMillion = int64(j)
			}
		}()
	}
	group.Wait()
}
func TestCheckedArithmetic(t *testing.T) {
	for _, pair := range [][2]int64{{math.MaxInt64, 1}, {-1, 0}, {0, -1}} {
		if _, err := checkedAdd(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted add %v", pair)
		}
	}
	for _, pair := range [][2]int64{{math.MaxInt64, 2}, {-1, 0}, {0, -1}} {
		if _, err := checkedMultiply(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted multiply %v", pair)
		}
	}
	if got, err := checkedAdd(math.MaxInt64-1, 1); err != nil || got != math.MaxInt64 {
		t.Fatal(got, err)
	}
	if got, err := checkedMultiply(math.MaxInt64, 0); err != nil || got != 0 {
		t.Fatal(got, err)
	}
}
func TestMalformedJSONAndZeroSnapshot(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`[]`), []byte(`null`), {0xff}, []byte(`{} {}`), []byte(`{"v":`)} {
		if _, err := ParseSnapshot(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if _, err := CanonicalBytes(Snapshot{}); err == nil {
		t.Fatal("canonical zero snapshot")
	}
	if _, err := Evaluate(Snapshot{}, "x", RawUsage{}, DefaultEligibility()); err == nil {
		t.Fatal("evaluated zero snapshot")
	}
	if (Snapshot{}).Candidates() != nil {
		t.Fatal("zero snapshot candidates")
	}
}
func TestCanonicalASCIIAndValidation(t *testing.T) {
	c := DefaultEligibility()
	c.UsageType = "é😀<&>\n"
	raw, err := CanonicalBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"usage_type":"\u00e9\ud83d\ude00<&>\n"`)) {
		t.Fatalf("wrong ASCII escaping: %s", raw)
	}
	for _, b := range raw {
		if b > 127 {
			t.Fatal("non-ASCII canonical bytes")
		}
	}
	e := AcceptanceOutcome{Status: "accepted"}
	if _, err = CanonicalHash(e); err == nil {
		t.Fatal("hashed invalid acceptance")
	}
	e.Status = "conflict"
	hash, err := CanonicalHash(e)
	if err != nil || len(hash) != 64 {
		t.Fatal(hash, err)
	}
}
func TestDirectGoValuesValidated(t *testing.T) {
	c := fixtureNamed(t, "openai_cache")
	s, err := ParseSnapshot(c.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Evaluate(s, c.SelectedEndpoint, RawUsage{InputTokens: -1}, DefaultEligibility()); err == nil {
		t.Fatal("negative Go usage")
	}
	observed := DefaultEligibility()
	observed.AppMarkup = -1
	if err = RequireEligible(observed); err == nil {
		t.Fatal("negative Go facts")
	}
	var envelope TerminalEnvelope
	valid := fixtureNamed(t, "envelope_settle")
	if err = json.Unmarshal(valid.Input, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.SnapshotVersion = 2
	if err = ValidateEnvelope(s, envelope); err == nil {
		t.Fatal("invalid Go envelope")
	}
}
func TestFreezeCacheHalfEvenAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		provider           string
		input, read, write int64
	}{{"openai", 1, 0, 1}, {"openai", 3, 2, 4}, {"anthropic", 5, 0, 6}, {"anthropic", 15, 2, 19}, {"openai", 2, 1, 2}, {"openai", 6, 3, 8}} {
		r, err := freezeRates(tc.provider, tc.input, 0, nil)
		if err != nil || r.CachedInputMicroPerMillion != tc.read || r.CacheCreationMicroPerMillion != tc.write {
			t.Fatalf("%+v: %+v %v", tc, r, err)
		}
	}
	if _, err := freezeRates("openai", math.MaxInt64, 0, nil); err == nil {
		t.Fatal("overflow accepted")
	}
}
