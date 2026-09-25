//go:build !linux

package privatemode

import (
	"context"
	"errors"
	"net/http"
)

func Start(context.Context) (*http.Client, error) {
	return nil, errors.New("privatemode: attested proxy requires Linux")
}

func startProcess(ctx context.Context) (*http.Client, <-chan struct{}, error) {
	client, err := Start(ctx)
	return client, nil, err
}

func ProxyEntrypoint() bool { return false }
