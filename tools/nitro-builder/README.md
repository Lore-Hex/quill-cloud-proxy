# Pinned Nitro EIF builder

This is a build tool, not the enclave image or a serving workload. It has no
AWS credentials and does not run enclaves. The AWS CLI source and both base
images are pinned; Cargo uses the upstream lock file. CLI 1.5.3 includes the
registry-credential selection and log/symlink fixes from the upstream release.

Build on linux/amd64, publish once to the dedicated ECR builder repository,
then commit its **registry manifest digest** as the release workflow input.
Do not use a tag or rebuild this Dockerfile during an enclave release. The
resulting builder digest also freezes the kernel, init, NSM and LinuxKit blobs.

The build needs only a Docker socket and an output directory. Never mount a
home directory or pass AWS credentials into it. Run it on an isolated CI runner,
not on a production gateway. The output EIF and PCR0/1/2 come from that same
build, and a signed manifest binds them to the source commit and builder.

The mutable Alpine package repository used when initially creating this image
does not promise byte-identical builder rebuilds. Each builder update therefore
gets a new reviewed digest. Releasing an enclave uses the existing digest, not
this package-install step.
