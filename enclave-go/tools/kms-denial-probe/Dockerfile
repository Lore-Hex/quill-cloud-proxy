FROM --platform=$BUILDPLATFORM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY tools/kms-denial-probe/ ./tools/kms-denial-probe/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -tags cloud_aws -o /probe ./tools/kms-denial-probe

FROM scratch
COPY --from=build /probe /probe
ENTRYPOINT ["/probe"]
