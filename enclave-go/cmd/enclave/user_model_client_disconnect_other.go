//go:build !linux

package main

import (
	"context"
	"io"
	"log"
)

func init() {
	// Non-Linux targets lack the poll/MSG_PEEK primitive used to detect a
	// buffered caller disappearing without consuming a pipelined next request.
	log.Printf("user-model client disconnect detection is unavailable on this OS")
}

func userModelClientDisconnect(context.Context, io.Writer) <-chan struct{} { return nil }
