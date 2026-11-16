package types

import (
	"bytes"
	"errors"
)

// DeidentifyFlag deliberately rejects null and non-booleans: a misspelled
// privacy setting must not silently send an unprotected request.
type DeidentifyFlag bool

func (f *DeidentifyFlag) UnmarshalJSON(raw []byte) error {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		*f = true
	case "false":
		*f = false
	default:
		return errors.New("deidentify must be a boolean")
	}
	return nil
}
