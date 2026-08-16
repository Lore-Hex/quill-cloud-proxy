//go:build !linux

package main

import (
	"context"
	"io"
)

func userModelClientDisconnect(context.Context, io.Writer) <-chan struct{} { return nil }
