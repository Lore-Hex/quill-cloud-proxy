package speculation

import "math"

// CostCeiling computes B with separate upward rounding and checked int64 math.
func CostCeiling(inputBound, inputRate, outputLimit, outputRate, fees any) (value int64, err error) {
	defer refusal(&err)
	args := []any{inputBound, inputRate, outputLimit, outputRate, fees}
	n := make([]int64, len(args))
	for i, v := range args {
		n[i] = integer(v)
	}
	total := n[4]
	for _, pair := range [][2]int64{{n[0], n[1]}, {n[2], n[3]}} {
		count, rate := pair[0], pair[1]
		require(rate == 0 || count <= math.MaxInt64/rate, "overflow")
		product := count * rate
		rounded := product / 1000000
		if product%1000000 != 0 {
			rounded++
		}
		require(total <= math.MaxInt64-rounded, "overflow")
		total += rounded
	}
	return total, nil
}

// WorkspaceAllowance computes W from the trusted tier ceiling and paid headroom.
func WorkspaceAllowance(tierCeiling, paidHeadroom any) (value int64, err error) {
	defer refusal(&err)
	tier := integer(tierCeiling)
	paid := integer(paidHeadroom)
	return min(tier/100, paid/10, int64(1000000)), nil
}
