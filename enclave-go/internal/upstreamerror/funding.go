package upstreamerror

import "strings"

// fundingMarkers are the words providers use when the calling account is out
// of money. They word it freely and not always with a 402: Venice answers 402
// "Insufficient USD or Diem balance ... add credits", Anthropic 400 "Your
// credit balance is too low", OpenAI 429 insufficient_quota "You exceeded
// your current quota". Matched lower-cased against the parsed message and the
// error code/type.
var fundingMarkers = []string{
	"account balance",
	"add credits",
	"add more credits",
	"balance is too low",
	"balance too low",
	"billing hard limit",
	"credit balance",
	"credits exhausted",
	"diem balance",
	"exceeded your current quota",
	"insufficient balance",
	"insufficient credit",
	"insufficient funds",
	"insufficient usd",
	"insufficient_quota",
	"not enough credits",
	"out of credits",
	"payment required",
	"prepaid credit",
	"top up your",
	"top-up",
}

var fundingCodes = map[string]bool{
	"billing_hard_limit_reached": true,
	"insufficient_balance":       true,
	"insufficient_quota":         true,
	"payment_required":           true,
	"prepaid_credit_exhausted":   true,
}

// FundingExhausted reports whether a provider failure says the account that
// called it is out of funds: an HTTP 402, or funding wording on any 4xx.
// The account is TrustedRouter's on a prepaid route and the customer's on a
// BYOK route; callers decide which from the attempted route. A failure with
// no provider status (a transport error, a local failure) never is.
func FundingExhausted(err error) bool {
	if err == nil || IsLocal(err) {
		return false
	}
	status, ok := Status(err)
	if !ok || status < 400 || status >= 500 {
		return false
	}
	if status == 402 {
		return true
	}
	d := Parse(err)
	for _, value := range []any{d.Code, d.Type} {
		if s, ok := value.(string); ok && fundingCodes[strings.ToLower(strings.TrimSpace(s))] {
			return true
		}
	}
	message := strings.ToLower(d.Message)
	for _, marker := range fundingMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
