package upstreamerror

import (
	"errors"
	"regexp"
)

// requestIDPattern admits only a plain identifier: no spaces, quotes or
// separators that could smuggle other header or body content.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}$`)

// RequestID returns the provider's request ID carried by a provider failure,
// or "" when there is none or it is not a bounded plain identifier. It lets an
// operator name the failed call to the provider without the request content.
func RequestID(err error) string {
	var carrier interface{ UpstreamRequestID() string }
	if err == nil || !errors.As(err, &carrier) {
		return ""
	}
	id := carrier.UpstreamRequestID()
	if !requestIDPattern.MatchString(id) || sanitizeText(id) != id {
		return ""
	}
	return id
}
