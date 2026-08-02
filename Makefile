# PhiGate build tooling.
#
# tree-sitter bindings require cgo, so CGO_ENABLED=1 and a C compiler (gcc/clang)
# are mandatory for every target.

export CGO_ENABLED := 1

BINARY := bin/phigate
PKG    := ./...

.PHONY: all build run test tidy fmt vet clean

all: build

build:
	go build -o $(BINARY) ./cmd/phigate

run:
	go run ./cmd/phigate

test:
	go test $(PKG)

tidy:
	go mod tidy

fmt:
	go fmt $(PKG)

vet:
	go vet $(PKG)

clean:
	rm -rf bin
