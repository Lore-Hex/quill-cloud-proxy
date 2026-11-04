package trustedrouter

import "strings"

const RetiredModelMessage = "Custom models and user-provided models have been retired. Choose a catalog model."

// IsRetiredModelID is shared by ingress and authorization, including internal
// orchestration calls that do not pass through the public request handler.
func IsRetiredModelID(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	for _, prefix := range []string{"tr-custom-model/", "tr-user-model/", "trustedrouter/user-", "nyte/user-"} {
		if strings.HasPrefix(model, prefix) {
			return true
		}
	}
	return false
}

func rejectRetiredModels(model string, fallbacks []string) *ControlPlaneError {
	for _, candidate := range append([]string{model}, fallbacks...) {
		if IsRetiredModelID(candidate) {
			return &ControlPlaneError{StatusCode: 410, Type: "model_not_supported", Message: RetiredModelMessage}
		}
	}
	return nil
}
