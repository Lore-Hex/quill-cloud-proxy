# Rebuild an AWS gateway release without registry credentials

Use a disposable Linux amd64 builder with Docker, Buildx, jq, Python 3 and
Cosign 2.6.5. This test never contacts a production enclave, reads a key,
or changes a release. It rebuilds both the application image and the Nitro
converter from the chosen release's source. The converter uses AWS's pinned
public source distribution, including its published boot blobs; it is not
a from-source rebuild of the boot kernel.

Select a protected-main commit and EIF digest from an independently reviewed
release manifest. On the current verifier checkout:

```bash
git worktree add --detach /tmp/approved-qcp-source "$SOURCE"
export QCP_REBUILD_SOURCE=/tmp/approved-qcp-source
export AWS_EIF_MANIFEST="$PWD/trust-page/trust/eif/$SOURCE/$EIF/manifest.json"
export AWS_EIF_SIGNATURE="$AWS_EIF_MANIFEST.bundle"
export NITRO_BUILDER_SOURCE=public-source REBUILD_EVIDENCE=/tmp/comparison.json
bash tools/verify-pcr0.sh
```

The verifier authenticates the manifest under the protected publisher's
identity and checks its source commit before building. It compares the
application image ID, PCR0/1/2, full EIF SHA-256 and byte count. All six
must match. Identical PCRs alone do not prove identical files. The independent
rebuild workflow runs that comparison on two separate hosted runners without
cloud credentials. A missing result or a mismatch is a failed comparison,
not proof of tampering or a reason to broaden any key policy.

This compares a named release, not the running fleet. Confirm the serving PCR0
separately using a fresh, TLS-bound challenge. The test neither admits the
candidate nor changes the automated production rollout.
