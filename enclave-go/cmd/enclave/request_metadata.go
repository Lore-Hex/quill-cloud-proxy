package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Request metadata starts in observe mode so adding attribution support cannot
// turn previously accepted inference traffic into hard failures. Once
// production telemetry is clean and the control-plane capability is deployed,
// operators can set TR_REQUEST_METADATA_ENFORCEMENT=enforce.
func validateOrObserveRequestMetadata(req *types.OpenAIChatRequest, requestLogID string) error {
	if req == nil {
		return nil
	}
	if err := req.Tags.ValidationError(); err != nil {
		if requestMetadataEnforced() {
			return err
		}
		logDroppedRequestMetadata(requestLogID, "tags")
		req.Tags = nil
	}
	if err := req.ValidateAttribution(); err != nil {
		if requestMetadataEnforced() {
			return err
		}
		logDroppedRequestMetadata(requestLogID, "attribution")
		clearInvalidAttribution(req)
	}
	return nil
}

func requestMetadataEnforced() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TR_REQUEST_METADATA_ENFORCEMENT"))) {
	case "1", "true", "strict", "enforce":
		return true
	default:
		return false
	}
}

func clearInvalidAttribution(req *types.OpenAIChatRequest) {
	if req == nil {
		return
	}
	req.User = ""
	req.SessionID = ""
	req.Trace = nil
	req.App = ""
	req.HTTPReferer = ""
	req.AppCategories = nil
}

func logDroppedRequestMetadata(requestLogID, kind string) {
	fmt.Fprintf(
		os.Stderr,
		"enclave.request_metadata_dropped request_log_id=%q kind=%q enforcement=%q\n",
		requestLogID,
		kind,
		"observe",
	)
}
