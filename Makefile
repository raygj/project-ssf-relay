BINARY   := ssf-relay
BIN_DIR  := bin
CMD      := ./cmd/ssf-relay

REGISTRY ?= ghcr.io/example/ssf
IMAGE    := $(REGISTRY)/ssf/relay:dev

DEMO_COMPOSE := docker-compose -f docker-compose.demo.yml

.PHONY: build test lint docker push clean demo demo-up demo-down demo-trigger demo-bundle

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY) $(CMD)

test:
	go test ./...

lint:
	go vet ./...

docker:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY)-linux $(CMD)
	docker build -f Dockerfile.push -t $(IMAGE) .

push: docker
	docker save $(IMAGE) -o /tmp/ssf-relay.tar
	crane push /tmp/ssf-relay.tar $(IMAGE) --insecure

clean:
	rm -rf $(BIN_DIR)

demo-up:
	$(DEMO_COMPOSE) up -d --build

demo-down:
	$(DEMO_COMPOSE) down -v

demo-trigger:
	./scripts/demo-trigger.sh

demo:
	./scripts/demo.sh

# Pack demo-only tarball for GitHub release assets (see demo/BUNDLE-README.md).
# Usage: make demo-bundle VERSION=v0.1.1-demo
demo-bundle:
	@mkdir -p dist
	@chmod +x scripts/build-demo-bundle.sh scripts/demo-trigger.sh scripts/demo-bundle-up.sh
	@./scripts/build-demo-bundle.sh $(or $(VERSION),$(shell git describe --tags --exact-match 2>/dev/null || echo dev))
