//go:build cloud_gcp

// Package entropy: GCP Confidential Space variant.
//
// Why a no-op:
//   The AWS variant exists because Nitro Enclaves boot with a starved
//   /dev/urandom — there's no hardware RNG visible to the guest kernel
//   pool until /dev/random unblocks, and TLS keypairs minted in that
//   window come from low-entropy bytes. NSM exposes a hypervisor-side
//   RNG via ioctl, so we seed the kernel pool from it.
//
//   Confidential Space VMs run AMD SEV-SNP on real GCE host hardware.
//   The guest kernel sees the host's /dev/urandom path and the AMD
//   CPU's RDRAND/RDSEED instructions, plus standard virtio-rng entry.
//   Boot-time entropy is fine; no seeding needed.
package entropy

// Seed is a no-op on GCP. The signature matches the AWS variant so
// cmd/enclave/main.go can call it unconditionally.
func Seed() error { return nil }
