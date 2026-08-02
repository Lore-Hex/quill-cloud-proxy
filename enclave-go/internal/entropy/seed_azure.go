//go:build cloud_azure

// Package entropy: Azure Confidential VM variant.
//
// Why a no-op, same as GCP:
//
//	The AWS variant exists for a Nitro-specific problem. A Nitro Enclave
//	boots with a starved /dev/urandom — no hardware RNG is visible to the
//	guest kernel pool until /dev/random unblocks, so a TLS keypair minted
//	in that window comes from low-entropy bytes. NSM exposes a
//	hypervisor-side RNG via ioctl, so the AWS variant seeds the pool from
//	it before anything mints a key.
//
//	An Azure Confidential VM has none of that. It is AMD SEV-SNP on real
//	Azure host hardware: the guest kernel gets the CPU's RDRAND/RDSEED
//	and the standard virtio-rng path, exactly like a Confidential Space
//	VM. Boot-time entropy is adequate and there is nothing to seed from.
//
//	Seeding anyway would be worse than useless — it would mean inventing
//	an entropy source to satisfy a signature, and an invented entropy
//	source in a TEE is a security defect, not a stub.
package entropy

// Seed is a no-op on Azure. The signature matches the AWS and GCP
// variants so cmd/enclave/main.go can call it unconditionally.
func Seed() error { return nil }
