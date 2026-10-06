package trustedrouter

import "errors"

// This marker distinguishes the local seed guard from ordinary router errors,
// whose public response bytes (including unseeded errors) must remain unchanged.
type videoRoutingConstraintError struct{ cause *ControlPlaneError }

func (e *videoRoutingConstraintError) Error() string { return e.cause.Error() }
func (e *videoRoutingConstraintError) Unwrap() error { return e.cause }

func IsVideoRoutingUnavailable(err error) bool {
	var routing *videoRoutingConstraintError
	return errors.As(err, &routing)
}

// VideoRoutingUnavailable reports a seeded authorization with no compatible route.
func VideoRoutingUnavailable() error {
	return &videoRoutingConstraintError{cause: &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 503,
		Type:    "video_routing_unavailable",
		Message: "control plane returned a video route outside the required provider constraints"}}
}
