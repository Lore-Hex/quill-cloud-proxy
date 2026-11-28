# Build once, publish, and pin the resulting image digest in the EIF workflow.
# No AWS credentials belong in this image or in its build arguments.
FROM rust:1.94.1-alpine@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS compiler
RUN apk add --no-cache build-base clang-dev cmake git linux-headers openssl-dev openssl-libs-static perl pkgconf
WORKDIR /src
ADD --checksum=sha256:f40ccfe9ab4fcfc4d4ff1f8f7debb7aa2f6a3784f7c245faaadacba14cc0bf00 https://codeload.github.com/aws/aws-nitro-enclaves-cli/tar.gz/536dca352e130e23bb39b6227753c91ad702048d /tmp/nitro.tar.gz
RUN tar -xzf /tmp/nitro.tar.gz --strip-components=1 -C /src
# These two upstream metadata fields describe the builder host, not the
# workload. Keep the Docker image identity; the signed SLSA statement carries
# the real build invocation and time. Do not change how PCRs or the CRC are made.
COPY deterministic-metadata.patch /tmp/deterministic-metadata.patch
RUN git apply --check /tmp/deterministic-metadata.patch && git apply /tmp/deterministic-metadata.patch
ENV OPENSSL_STATIC=1 RUSTFLAGS="-C target-feature=+crt-static" CARGO_BUILD_JOBS=4
RUN cargo build --locked --release --target x86_64-unknown-linux-musl --bin nitro-cli

FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:d724666caf360c5cd021688d52575551d07897fd54b1e56e9d81a6e697e7b7d4
COPY --from=compiler /src/target/x86_64-unknown-linux-musl/release/nitro-cli /usr/local/bin/nitro-cli
COPY --from=compiler /src/blobs/x86_64/ /usr/share/nitro_enclaves/blobs/
COPY --from=compiler /src/LICENSE /licenses/aws-nitro-enclaves-cli-LICENSE
COPY --from=compiler /src/NOTICE /licenses/aws-nitro-enclaves-cli-NOTICE
RUN mkdir -p /run/nitro_enclaves /var/log/nitro_enclaves /var/cache/nitro_enclaves /output \
    && touch /var/log/nitro_enclaves/nitro-cli.log \
    && chmod 0600 /var/log/nitro_enclaves/nitro-cli.log \
    && nitro-cli --version
ENV NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs NITRO_CLI_ARTIFACTS=/var/cache/nitro_enclaves
WORKDIR /output
ENTRYPOINT ["/usr/local/bin/nitro-cli"]
