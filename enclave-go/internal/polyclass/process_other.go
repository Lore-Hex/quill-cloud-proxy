//go:build !linux

package polyclass

func HelperEntrypoint() bool { return false }

func startHelper() (*process, error) { return nil, ErrUnavailable }
