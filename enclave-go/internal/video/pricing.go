package video

import "fmt"

const (
	videoCustomerPriceNumerator   = 120
	videoCustomerPriceDenominator = 100
)

// customerVideoPrice applies the video service fee using integer
// microdollars and rounds upward so the ledger never undercharges a fraction.
func customerVideoPrice(upstreamMicrodollars int) (int, error) {
	if upstreamMicrodollars <= 0 {
		return 0, fmt.Errorf("video quote: amount must be positive")
	}
	maxInt := int(^uint(0) >> 1)
	if upstreamMicrodollars > (maxInt-(videoCustomerPriceDenominator-1))/videoCustomerPriceNumerator {
		return 0, fmt.Errorf("video quote: amount is too large")
	}
	return (upstreamMicrodollars*videoCustomerPriceNumerator + videoCustomerPriceDenominator - 1) /
		videoCustomerPriceDenominator, nil
}
