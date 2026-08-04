# PhiGate build tooling.
#
# tree-sitter bindings require cgo, so CGO_ENABLED=1 and a C compiler (gcc/clang)
# are mandatory for every target. `make docker` builds an image that removes
# that requirement for anyone consuming PhiGate rather than developing it.

export CGO_ENABLED := 1

BINARY  := bin/phigate
EVALBIN := bin/phigate-eval
PKG     := ./...
IMAGE   := phigate:dev

.PHONY: all build run test test-race guarantees fmt vet tidy lint vulncheck docker corpus bench sweep rules clean help

all: build

## build: compile the gateway and the measurement harness
build:
	go build -o $(BINARY) ./cmd/phigate
	go build -o $(EVALBIN) ./cmd/phigate-eval

## run: start the gateway on :8080
run:
	go run ./cmd/phigate

## test: run the full suite
test:
	go test $(PKG)

## test-race: run the full suite under the race detector
test-race:
	go test -race -count=1 $(PKG)

## guarantees: run only the tests backing PhiGate's security and cost claims
guarantees:
	@echo "== no sensitive value survives redaction =="
	go test -count=1 ./internal/redact/ -run 'TestLeakCorpus|TestRedactIsSinglePass|TestMyNumber'
	@echo "== confined data never falls back to the cloud =="
	go test -count=1 ./internal/policy/
	@echo "== guard blocks catastrophe, allows prose =="
	go test -count=1 ./internal/sandbox/ -run 'TestGuardBlocks|TestGuardBypasses|TestGuardDoesNotBlockProse'
	@echo "== cache does not leak across sessions =="
	go test -count=1 ./internal/gateway/ -run 'TestTemplateCache|TestPolicyForbids|TestDebugEndpoint|TestAuthentication'

## corpus: fetch the public LogHub benchmark corpora into eval/corpus
corpus:
	@bash scripts/fetch-benchmark-corpus.sh eval/corpus

## bench: measure token reduction per pipeline stage on the fetched corpus
bench: build
	@test -d eval/corpus || $(MAKE) corpus
	@./$(EVALBIN) bench -dir eval/corpus

## sweep: report what would be detected in the fetched corpus, by class and rule
sweep: build
	@test -d eval/corpus || $(MAKE) corpus
	@./$(EVALBIN) leak -dir eval/corpus

## rules: print every redaction rule and its classification
rules: build
	@./$(BINARY) -rules

## fmt: format all Go source
fmt:
	go fmt $(PKG)

## vet: run go vet
vet:
	go vet $(PKG)

## tidy: tidy go.mod
tidy:
	go mod tidy

## lint: run golangci-lint if installed (config and timeout live in .golangci.yml)
lint:
	@command -v golangci-lint >/dev/null 2>&1 \
	  && golangci-lint run \
	  || echo "golangci-lint v2 not installed; skipping. Install with:" \
	     "go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2"

## vulncheck: scan dependencies and the stdlib for known vulnerabilities
vulncheck:
	@command -v govulncheck >/dev/null 2>&1 \
	  && govulncheck ./... \
	  || echo "govulncheck not installed; skipping. Install with:" \
	     "go install golang.org/x/vuln/cmd/govulncheck@latest"

## docker: build the distroless container image
docker:
	docker build -t $(IMAGE) .

## clean: remove build artifacts
clean:
	rm -rf bin

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
