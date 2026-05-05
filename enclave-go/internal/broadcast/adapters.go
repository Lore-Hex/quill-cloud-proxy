package broadcast

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type destinationAdapter interface {
	Type() string
	Deliver(
		ctx context.Context,
		httpc *http.Client,
		cache *byokcache.Cache,
		destination trustedrouter.BroadcastDestination,
		generation Generation,
		input any,
		output string,
	) error
}

var destinationAdapters = map[string]destinationAdapter{
	"posthog": postHogAdapter{},
	"webhook": webhookOTLPAdapter{},
}

func adapterFor(destinationType string) (destinationAdapter, bool) {
	adapter, ok := destinationAdapters[destinationType]
	return adapter, ok
}

func unsupportedDestinationError(destinationType string) error {
	return fmt.Errorf("unsupported destination type %q", destinationType)
}

type postHogAdapter struct{}

func (postHogAdapter) Type() string {
	return "posthog"
}

func (postHogAdapter) Deliver(
	ctx context.Context,
	httpc *http.Client,
	cache *byokcache.Cache,
	destination trustedrouter.BroadcastDestination,
	generation Generation,
	input any,
	output string,
) error {
	apiKey, err := resolveSecret(ctx, cache, generation.WorkspaceID, destination.APIKeyContext, destination.EncryptedAPIKey)
	if err != nil {
		return err
	}
	return postJSON(ctx, httpc, posthogURL(destination.Endpoint), nil, posthogPayload(apiKey, generation, input, output))
}

type webhookOTLPAdapter struct{}

func (webhookOTLPAdapter) Type() string {
	return "webhook"
}

func (webhookOTLPAdapter) Deliver(
	ctx context.Context,
	httpc *http.Client,
	cache *byokcache.Cache,
	destination trustedrouter.BroadcastDestination,
	generation Generation,
	input any,
	output string,
) error {
	headers, err := resolveHeaders(ctx, cache, generation.WorkspaceID, destination)
	if err != nil {
		return err
	}
	method := destination.Method
	if method == "" {
		method = http.MethodPost
	}
	return sendJSON(ctx, httpc, method, destination.Endpoint, headers, otlpPayload(generation, true, input, output))
}
