VERSION ?= 0.1.0
LDFLAGS := -s -w
BIN := bin

.PHONY: all server agent agents test run-server clean docker

all: test server agents

server:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/vigil-server ./cmd/vigil-server

agent:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/vigil-agent ./cmd/vigil-agent

# cross-compiled agents for every supported platform
agents:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/vigil-agent-linux-amd64 ./cmd/vigil-agent
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/vigil-agent-linux-arm64 ./cmd/vigil-agent
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/vigil-agent-windows-amd64.exe ./cmd/vigil-agent
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/vigil-agent-darwin-arm64 ./cmd/vigil-agent

test:
	go vet ./...
	go test ./...

run-server: server
	VIGIL_ADMIN_PASSWORD=change-me-please $(BIN)/vigil-server -data ./data -rules ./rules

docker:
	docker build -f deploy/docker/Dockerfile -t vigil-server:$(VERSION) .

clean:
	rm -rf $(BIN)
