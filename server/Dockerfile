# Build one static binary, then ship only it: no shell, no libc, no package tree.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay
# An empty /data already owned by the runtime user, so a fresh volume is
# writable and the store survives a restart.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM scratch
COPY --from=build /out/relay /relay
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV RELAY_ADDR=0.0.0.0:8010 \
    RELAY_STATE_PATH=/data/channels.json
VOLUME ["/data"]
EXPOSE 8010
ENTRYPOINT ["/relay"]
