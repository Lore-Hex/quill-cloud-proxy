package spendlease

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEstimatorPythonParityFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/estimator_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name     string          `json:"name"`
		Request  EstimateRequest `json:"request"`
		Catalog  Catalog         `json:"catalog"`
		Expected *int64          `json:"expected_micro"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := Estimate(fixture.Catalog, fixture.Request)
			if err != nil {
				t.Fatal(err)
			}
			if (got == nil) != (fixture.Expected == nil) || got != nil && *got != *fixture.Expected {
				t.Fatalf("estimate = %v, want %v", pointerValue(got), pointerValue(fixture.Expected))
			}
		})
	}
}

func pointerValue(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
