# Certio — build targets.
#
# The dashboard is built with Nuxt, copied into cmd/certio/dist and embedded
# into the binary, so `make build` produces one self-contained artifact.

BINARY      := certio
MODULE      := github.com/jkaninda/certio
IMAGE       := jkaninda/certio
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

WEB_DIR   := web
WEB_OUT   := $(WEB_DIR)/.output/public
EMBED_DIR := cmd/certio/dist

GO_FILES := $(shell find . -name '*.go' -not -path './web/*')

.DEFAULT_GOAL := build

## help: list the available targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | sort

## deps: download Go modules and install frontend packages
.PHONY: deps
deps:
	go mod download
	cd $(WEB_DIR) && npm ci

## ui: build the Nuxt dashboard and stage it for embedding
.PHONY: ui
ui:
	cd $(WEB_DIR) && npm run build
	rm -rf $(EMBED_DIR)
	mkdir -p $(EMBED_DIR)
	cp -r $(WEB_OUT)/. $(EMBED_DIR)/
	# The placeholder is tracked and the rm above takes it with it. Without it a
	# fresh clone cannot build at all: //go:embed needs the directory to exist,
	# and it is otherwise entirely gitignored.
	touch $(EMBED_DIR)/.gitkeep

## build: build the single binary with the dashboard embedded
.PHONY: build
build: ui
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/certio
	@echo "built bin/$(BINARY) $(VERSION)"

## build-api: build without rebuilding the dashboard (fast backend iteration)
.PHONY: build-api
build-api:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/certio

## run: build and run the server locally
.PHONY: run
run: build-api
	./bin/$(BINARY) serve

## dev: run the API and the Nuxt dev server together
.PHONY: dev
dev:
	@echo "API   → http://localhost:8080"
	@echo "UI    → http://localhost:3000 (proxies /api to 8080)"
	@$(MAKE) -j2 dev-api dev-ui

.PHONY: dev-api
dev-api:
	go run ./cmd/certio serve

.PHONY: dev-ui
dev-ui:
	cd $(WEB_DIR) && npm run dev

## test: run the Go test suite
.PHONY: test
test:
	go test ./... -race

## test-short: skip the openssl cross-checks
.PHONY: test-short
test-short:
	go test ./... -short

## cover: run tests and open the coverage report
.PHONY: cover
cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

## lint: run gofmt, go vet and golangci-lint when available
.PHONY: lint
lint:
	@test -z "$$(gofmt -l $(GO_FILES))" || (echo "gofmt needed:"; gofmt -l $(GO_FILES); exit 1)
	go vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "golangci-lint not installed; skipped"

## fmt: format the Go sources
.PHONY: fmt
fmt:
	gofmt -w $(GO_FILES)

## typecheck: type-check the dashboard
.PHONY: typecheck
typecheck:
	cd $(WEB_DIR) && npm run typecheck

## docker: build the multi-stage container image
.PHONY: docker
docker:
	docker build -f docker/Dockerfile -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

## docker-push: build and push a multi-arch image
.PHONY: docker-push
docker-push:
	docker buildx build -f docker/Dockerfile \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest --push .

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf bin coverage.out coverage.html
	rm -rf $(WEB_DIR)/.output $(WEB_DIR)/.nuxt
	find $(EMBED_DIR) -mindepth 1 -not -name '.gitkeep' -delete 2>/dev/null || true

## snapshot: build the full release locally without publishing anything
.PHONY: snapshot
snapshot:
	@command -v goreleaser >/dev/null || \
		(echo "goreleaser is not installed: https://goreleaser.com/install"; exit 1)
	goreleaser release --snapshot --clean --skip=publish
	@echo "artifacts in dist/"

## release: cross-compile, archive and publish the current tag
# CI runs this on a tag. Locally it needs GITHUB_TOKEN and a clean tree at a tag.
.PHONY: release
release:
	@command -v goreleaser >/dev/null || \
		(echo "goreleaser is not installed: https://goreleaser.com/install"; exit 1)
	goreleaser release --clean
