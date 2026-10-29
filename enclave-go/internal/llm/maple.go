package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/maple"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type mapleStart func(context.Context, string, string, []byte) (int, io.ReadCloser, error)

// This candidate is intentionally not registered in multiClient until every
// serving image contains the measured helper and its cloud egress is qualified.
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
		return errors.New("llm/maple: encrypted request verification failed")
	}
	if response == nil {
		return errors.New("llm/maple: missing encrypted response")
	}
	defer response.Close()
	if status != http.StatusOK {
		if status < 400 || status > 599 {
			return errors.New("llm/maple: invalid encrypted response status")
		}
		return &upstreamHTTPError{status: status, body: "Maple encrypted upstream request failed"}
	}
	upstreamerror.Open(out)
	if err := translateOpenAIStreamToAnthropicForProvider(response, out, "maple"); err != nil {
		return errors.New("llm/maple: encrypted response incomplete or invalid")
	}
	return nil
}
