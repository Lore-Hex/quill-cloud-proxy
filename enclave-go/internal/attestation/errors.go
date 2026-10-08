package attestation

import "errors"

// ErrIssuerUnavailable is temporary issuance failure, never valid evidence.
var ErrIssuerUnavailable = errors.New("attestation issuer unavailable")
