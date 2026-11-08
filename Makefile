GO ?= go
GOFMT ?= gofmt
SHELLCHECK ?= shellcheck
IMAGE ?= unifi-os-le-cert-deployer:local

.PHONY: check fmt-check lint-sh cross-build build image image-test

check: fmt-check lint-sh
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -race ./...
	$(MAKE) cross-build

fmt-check:
	@unformatted=$$($(GOFMT) -l cmd/unifi-cert-upload/*.go); if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi

lint-sh:
	$(SHELLCHECK) scripts/*.sh

cross-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o /dev/null ./cmd/unifi-cert-upload
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o /dev/null ./cmd/unifi-cert-upload

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/unifi-cert-upload ./cmd/unifi-cert-upload

image:
	docker buildx build --load -t $(IMAGE) .

image-test: image
	scripts/image-test.sh $(IMAGE)
