//go:build cloud_aws && !linux

package privatemode

import (
	"context"
	"errors"
)

func platformEnvironment(context.Context) ([]string, func(), error) {
	return nil, nil, errors.New("privatemode: Nitro requires Linux")
}
