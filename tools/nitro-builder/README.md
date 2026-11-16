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

## Publish a release

After the approved artifact infrastructure exists and the reviewed builder
digest has been pushed, dispatch `publish-aws-eif.yml` on main. It builds the
application from that exact main commit, converts it once with the pinned
builder, independently reads back its measurements and CRC, and signs the
manifest with the workflow's GitHub identity. The publication summary gives
the immutable S3 prefixes in both regions. Publication does not admit a PCR0
or start an instance.

The uploader uses the parent project's locked AWS SDK dependencies. Its
create-only uploads can resume after interruption; it checks S3's SHA-256 and
size, authenticates the stored signature, and writes `manifest.json` last.
An existing different image or manifest is an error, never an overwrite.

## Prepare a candidate template

Download `manifest.json` and `manifest.json.bundle` from the summary's prefix.
Install the repository's pinned Cosign verifier. With the AWS rollout fence
held, set `AWS_EIF_MANIFEST`, `AWS_EIF_SIGNATURE`, and the full
`AWS_EIF_SOURCE_COMMIT`. Set `CANDIDATE_TEMPLATE_ONLY=1` when running the compute
phase. It authenticates the CI identity and checks the regional S3 artifact
before creating a template version. In this mode it never updates the default
template, Auto Scaling Group, target group, or DNS. It refuses a serving group
that follows `$Latest`, since adding a version would then not be isolated.

The generated host startup downloads the EIF and checks its exact SHA-256 and
size before starting it. It does not contain a build-enclave command or select
the latest enclave container tag. The host AMI and Nitro CLI package are pinned
independently from the EIF builder; the host does not supply measured blobs.

Widen public/runtime pins from the authenticated CI manifest before launching
the isolated candidate. Once the attested candidate matches that PCR0, promote
only its explicit numeric template version. A new template is not evidence
that a candidate booted successfully. The staged release and abort gates in
the attested-secret-release plan still apply.
