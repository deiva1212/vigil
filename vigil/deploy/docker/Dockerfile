# Build: docker build -f deploy/docker/Dockerfile -t vigil-server .
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/vigil-server ./cmd/vigil-server \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/agents/vigil-agent-linux-amd64 ./cmd/vigil-agent \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /out/agents/vigil-agent-linux-arm64 ./cmd/vigil-agent \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/agents/vigil-agent-windows-amd64.exe ./cmd/vigil-agent \
 && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /out/agents/vigil-agent-darwin-arm64 ./cmd/vigil-agent

FROM alpine:3.20
RUN adduser -D -H vigil && mkdir -p /var/lib/vigil && chown vigil /var/lib/vigil
COPY --from=build /out/vigil-server /opt/vigil/vigil-server
COPY --from=build /out/agents /opt/vigil/agents
COPY rules /opt/vigil/rules
COPY feeds /opt/vigil/feeds
WORKDIR /opt/vigil
USER vigil
ENV VIGIL_DATA_DIR=/var/lib/vigil VIGIL_RULES_DIR=/opt/vigil/rules VIGIL_FEEDS_DIR=/opt/vigil/feeds VIGIL_SYSLOG_LISTEN=:5514
EXPOSE 8443 5514/udp 5514/tcp
VOLUME /var/lib/vigil
HEALTHCHECK CMD wget -q --no-check-certificate -O- https://127.0.0.1:8443/healthz || exit 1
ENTRYPOINT ["/opt/vigil/vigil-server"]
