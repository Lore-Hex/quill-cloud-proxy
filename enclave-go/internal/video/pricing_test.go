package video

import "testing"

func TestCustomerVideoPriceUsesIntegerMicrodollarsAndRoundsUp(t *testing.T) {
	tests := []struct {
		upstream int
		want     int
	}{
		{upstream: 1, want: 2},
		{upstream: 5, want: 6},
		{upstream: 810_000, want: 972_000},
		{upstream: 1_000_000, want: 1_200_000},
	}
	for _, tc := range tests {
		got, err := customerVideoPrice(tc.upstream)
		if err != nil {
			t.Fatalf("customerVideoPrice(%d): %v", tc.upstream, err)
		}
		if got != tc.want {
			t.Fatalf("customerVideoPrice(%d) = %d, want %d", tc.upstream, got, tc.want)
		}
	}
}

func TestCustomerVideoPriceRejectsInvalidAndOverflowingQuotes(t *testing.T) {
	for _, upstream := range []int{0, -1, int(^uint(0) >> 1)} {
		if _, err := customerVideoPrice(upstream); err == nil {
			t.Fatalf("customerVideoPrice(%d) unexpectedly succeeded", upstream)
		}
	}
}
