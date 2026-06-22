# Build (cross-compiles natively for the target arch via buildx).
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/exnode .

# Runtime: needs iptables for masquerade and runs with NET_ADMIN on the host.
FROM alpine:3.20
RUN apk add --no-cache iptables ip6tables
COPY --from=build /out/exnode /usr/local/bin/exnode
ENTRYPOINT ["/usr/local/bin/exnode", "-c", "/etc/exnode/config.yml"]
