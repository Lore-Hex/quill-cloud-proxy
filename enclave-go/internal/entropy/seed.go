//go:build cloud_aws

// Package entropy seeds the enclave's CSPRNG from the Nitro Security
// Module before any cryptographic operation runs.
//
// Why this matters: a freshly-booted Linux kernel inside an enclave has
// almost no entropy in /dev/random — the standard sources (interrupt
// timing, disk seeks, CPU jitter) are absent or attenuated under a
// hypervisor. Without seeding, crypto/rand can return immediately with
// poor entropy, which is exactly the wrong condition for generating the
// TLS server keypair we'll present to clients.
//
// Mitigation: pull random bytes from the NSM (which sources them from
// the Nitro hypervisor's hardware RNG, distinct from the guest kernel's
// pool) and write them into /dev/urandom via the RNDADDENTROPY ioctl, so
// the kernel's pool is properly seeded before crypto/rand reads it.
//
// This is the same shape the Brave nitriding-daemon uses; it's a
// mandatory step for any enclave that does TLS termination.
package entropy

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// rndAddEntropyArg matches struct rand_pool_info from <linux/random.h>:
//
//	int  entropy_count;
//	int  buf_size;
//	__u32 buf[];
type rndAddEntropyArg struct {
	EntropyCount int32
	BufSize      int32
	Buf          [256]byte
}

// RNDADDENTROPY = _IOW('R', 0x03, int [2])
// Encoded form (Linux ioctl numbering scheme), big-endian: 0x40085203.
const rndAddEntropy = 0x40085203

// Seed pulls 256 bytes of high-entropy randomness from the NSM and mixes
// them into the kernel's pool, repeating a few times to credit enough
// entropy for crypto/rand to be confident.
func Seed() error {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("entropy: open NSM: %w", err)
	}
	defer sess.Close()

	pool, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("entropy: open /dev/urandom: %w", err)
	}
	defer pool.Close()

	// Four rounds of 256 bytes each = 1 KiB of entropy added to the pool,
	// credited as 8 bits/byte. Linux caps the pool at 4 KiB anyway.
	for round := 0; round < 4; round++ {
		resp, err := sess.Send(&request.GetRandom{})
		if err != nil {
			return fmt.Errorf("entropy: NSM get_random round %d: %w", round, err)
		}
		if resp.GetRandom == nil || len(resp.GetRandom.Random) == 0 {
			return fmt.Errorf("entropy: empty NSM random response at round %d", round)
		}
		randomLen := len(resp.GetRandom.Random)
		if randomLen > len(rndAddEntropyArg{}.Buf) {
			return fmt.Errorf("entropy: NSM random response too large at round %d", round)
		}
		var arg rndAddEntropyArg
		copy(arg.Buf[:], resp.GetRandom.Random)
		arg.BufSize = int32(randomLen) // #nosec G115 -- randomLen is checked against Buf size.
		arg.EntropyCount = arg.BufSize * 8
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			pool.Fd(),
			rndAddEntropy,
			uintptr(unsafe.Pointer(&arg)), // #nosec G103 -- Linux ioctl requires rand_pool_info pointer.
		)
		if errno != 0 {
			return fmt.Errorf("entropy: RNDADDENTROPY round %d: %w", round, errno)
		}
	}
	return nil
}
