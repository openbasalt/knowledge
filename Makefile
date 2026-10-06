# Developer shortcuts. CI runs the same steps (.github/workflows/ci.yml).
GO ?= go

.PHONY: all build test lint validate sample conformance image

all: lint test validate

build:
	$(GO) build -o bin/ ./cmd/...

test:
	$(GO) test -race ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "run gofmt -w ."; exit 1)
	$(GO) vet ./...

validate:
	$(GO) run ./cmd/kb validate content/basalt

# Build the seed content with throwaway keys into dist/sample.
sample:
	scripts/sample-bundle.sh dist/sample

# Same, then run kbd on it and the conformance suite against it.
conformance:
	scripts/sample-bundle.sh dist/sample --conformance

image:
	docker build -t openbasalt-knowledge:dev .
