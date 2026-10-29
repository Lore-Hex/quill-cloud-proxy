//go:build cloud_aws && !linux

package maple

import (
	"context"
	"errors"
)

func platformEnvironment(context.Context) ([]string, func(), error) {
	return nil, nil, errors.New("maple: encrypted AWS egress requires Linux")
}
