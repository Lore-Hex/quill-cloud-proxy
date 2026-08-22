//go:build cloud_aws

package video

import (
	"context"
	"io"
)

func (c *DecartVideoClient) openRemoteVideo(
	context.Context,
	string,
	int,
) (io.ReadCloser, string, error) {
	// Decart is disabled on Nitro because its API and result hosts are not in
	// the measured parent tunnel allowlist. Keep this method fail-closed too.
	return nil, "", &InputError{Message: "video URL input is unavailable in this region"}
}
