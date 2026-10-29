//go:build !linux

package maple

import (
	"context"
	"errors"
)

func HelperEntrypoint() bool { return false }

func startProcess(context.Context, []byte, uint32) (process, error) {
	return process{}, errors.New("maple: encrypted adapter requires Linux")
}
