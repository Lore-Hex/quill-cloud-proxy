//go:build cloud_aws && !linux

package bootstrap

import (
	"context"
	"errors"
	"net"
)

func dialBootstrap(context.Context, uint32) (net.Conn, error) {
	return nil, errors.New("bootstrap: Nitro requires Linux")
}
