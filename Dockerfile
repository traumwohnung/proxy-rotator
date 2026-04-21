FROM golang:1.26-alpine AS builder

WORKDIR /build

# Copy all modules (proxy-gateway depends on proxy-kit, proxy-kit depends on httpcloak-patched via replace)
COPY proxy-kit/ ./proxy-kit/
COPY httpcloak-patched/ ./httpcloak-patched/
COPY proxy-gateway/go.mod proxy-gateway/go.sum ./proxy-gateway/

WORKDIR /build/proxy-gateway
RUN go mod download

COPY proxy-gateway/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o proxy-gateway-server .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/proxy-gateway/proxy-gateway-server /proxy-gateway-server

EXPOSE 8100

ENTRYPOINT ["/proxy-gateway-server"]
CMD ["/data/config/config.toml"]
