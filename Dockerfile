# Build a static binary, then ship it in an empty image.
# Renka is pure-Go (CGO disabled, SQLite via modernc), so the final image needs
# only the binary plus the CA roots for its one kind of outbound request (push
# gateways): no libc, no shell. Smallest possible surface.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /renka ./cmd/renka

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /renka /renka
# Run unprivileged. The /data volume must be writable by this uid:gid
# (see README: chown 10001:10001 ./data on the host).
USER 10001:10001
VOLUME /data
EXPOSE 8008
ENTRYPOINT ["/renka"]
CMD ["-config", "/data/renka.conf"]
