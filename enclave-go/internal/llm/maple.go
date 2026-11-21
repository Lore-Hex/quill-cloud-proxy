package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/maple"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type mapleStart func(context.Context, string, string, []byte) (int, io.ReadCloser, error)

const mapleStartFailedMessage = "llm/maple: encrypted request verification failed"

// mapleStartError keeps mapleStartFailedMessage as its text and unwraps to one
// of internal/maple's fixed start failures, for errorClass.
type mapleStartError struct{ failure error }

func (e *mapleStartError) Error() string { return mapleStartFailedMessage }
func (e *mapleStartError) Unwrap() error { return e.failure }

// Maple never reaches the ordinary HTTP adapter, including on verification
// failure. Public catalog activation is separately gated on qualified images.
func invokeMaple(ctx context.Context, key string, req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest, out io.Writer, option InvokeOptions) error {
	return invokeMapleWith(ctx, key, req, body, out, option, maple.Start)
}

func invokeMapleWith(ctx context.Context, key string, req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest, out io.Writer, option InvokeOptions, start mapleStart) error {
	if strings.TrimSpace(key) == "" || option.ProviderAPIKey != "" || req == nil || body == nil {
		return errors.New("llm/maple: managed encrypted route required")
	}
	if option.Provider != "maple" || option.UpstreamModel != maple.Model {
		return errors.New("llm/maple: model is not release-pinned")
	}
	if tier := strings.TrimSpace(req.ServiceTier); tier != "" && tier != "default" {
		return &upstreamHTTPError{status: http.StatusBadRequest, body: "Maple supports the default service tier only"}
	}
	messages, err := openAICompatibleMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	prepared, err := PrepareChatRequest("maple", maple.Model, req, body, messages, ChatPreparationOptions{})
	if err != nil {
		return err
	}
	defer clear(prepared.Bytes)
	status, response, err := start(ctx, key, option.ProviderCacheScope, prepared.Bytes)
	if err != nil {
		// internal/maple's own start failures ride along for the gateway's log
		// label (a rejected attestation reads as one), behind the same message
		// every caller, and through orchestration events every client, has
		// always seen.
		if failure := maple.StartFailure(err); failure != nil {
			return &mapleStartError{failure: failure}
		}
		return errors.New(mapleStartFailedMessage)
	}
	if response == nil {
		return errors.New("llm/maple: missing encrypted response")
	}
	defer response.Close()
	if status != http.StatusOK {
		if status < 400 || status > 599 {
			return errors.New("llm/maple: invalid encrypted response status")
		}
		return mapleUpstreamError(status, response)
	}
	upstreamerror.Open(out)
	if err := translateOpenAIStreamToAnthropicForProvider(response, out, "maple"); err != nil {
		return errors.New("llm/maple: encrypted response incomplete or invalid")
	}
	return nil
}

const mapleUpstreamFailedMessage = "Maple encrypted upstream request failed"

// mapleUpstreamError is Maple's error status with its error code when the
// helper relayed a known one (internal/maple allowlists it), so a refusal such
// as a 403 usage_limit_reached is told apart from a 403
// model_not_available_on_plan in logs and route health. The message stays the
// fixed one callers have always seen.
func mapleUpstreamError(status int, response io.Reader) error {
	var buf [64]byte
	n, _ := io.ReadFull(response, buf[:])
	code := maple.ErrorCode(string(buf[:n]))
	if code == "" {
		return &upstreamHTTPError{status: status, body: mapleUpstreamFailedMessage}
	}
	body, _ := json.Marshal(map[string]any{"error": map[string]string{
		"message": mapleUpstreamFailedMessage,
		"code":    code,
	}})
	return &upstreamHTTPError{status: status, body: string(body)}
}
