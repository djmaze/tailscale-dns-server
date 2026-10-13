# syntax=docker/dockerfile:1

# Build the DNS server.
FROM docker.io/library/golang:1.27-alpine3.23 AS build
WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal ./internal
# -buildvcs=false: the build context has no VCS metadata.
RUN CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags="-s -w" -o /out/tailscale-dns-server .

# Runtime image.
FROM docker.io/library/alpine:3.23
RUN apk add --no-cache ca-certificates

COPY --from=build /out/tailscale-dns-server /usr/local/bin/tailscale-dns-server

# Writable state dir (tsnet node key lives here).
RUN mkdir -p /data

# Configuration (flags of the same name override these, see --help):
#   DNS_DOMAIN         zone served by this DNS server (required)
#   TAILSCALE_DOMAIN   tailnet domain resolved via the tailscale plugin (required)
#   TS_HOSTNAME        hostname this node registers on the tailnet
#   TS_AUTHKEY         optional; when set, an embedded tailscale node (tsnet)
#                      is started, no external tailscaled is needed, and the
#                      server is additionally served on the node's tailnet IPs
#   DNS_PORT           DNS listen port (default 53)
#   TS_DIR             tsnet state dir (default $HOME/tsnet)
#   UPSTREAM_DNS       resolver(s) for names outside the tailnet, space
#                      separated: host[:port], [ipv6]:port and/or
#                      resolv.conf paths (default /etc/resolv.conf, which
#                      inside a container means the runtime's own resolver)
#   DEBUG              true enables the CoreDNS debug directive: prints
#                      debug-level log messages to stdout (default false)
# The loopback bind needs the port (root); the tailnet listeners do not.
# The domains intentionally have no default: the container fails fast unless
# both are set.
ENV TS_HOSTNAME=dns \
    HOME=/data

# tsnet stores the tailnet node key under $HOME/tsnet; keep it across restarts.
VOLUME /data

# Extra args reach the binary, e.g.
#   docker run -e DNS_DOMAIN=example.com -e TAILSCALE_DOMAIN=example.de \
#     -p 53:53/udp -p 53:53/tcp -v ts-dns-data:/data this-image
ENTRYPOINT ["/usr/local/bin/tailscale-dns-server"]
