//go:build !cloud_gcp

package main

import "errors"

func checkGCPCacheCustody() error { return errors.New("requires GCP gateway build") }
