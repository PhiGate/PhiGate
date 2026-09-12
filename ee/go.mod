// PhiGate Enterprise Edition.
//
// This is a separate Go module on purpose. The community edition's go.mod is
// the file a customer's security review reads, and it lists exactly one
// third-party dependency. EE needs several — an OpenTelemetry SDK, an embedded
// key/value store, a Redis client — and none of them may appear there.
//
// A nested module is what makes that structural rather than a matter of
// discipline: `go install github.com/phigate/phigate/cmd/phigate` resolves this
// file not at all, whatever /ee grows into.
module github.com/phigate/phigate/ee

go 1.26.0

require (
	github.com/alicebob/miniredis/v2 v2.39.0
	github.com/phigate/phigate v0.0.0
	github.com/redis/go-redis/v9 v9.22.0
	go.etcd.io/bbolt v1.5.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/mattn/go-pointer v0.0.1 // indirect
	github.com/tree-sitter/go-tree-sitter v0.25.0 // indirect
	github.com/tree-sitter/tree-sitter-go v0.25.0 // indirect
	github.com/tree-sitter/tree-sitter-python v0.25.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

// The two modules are developed and released together, so EE always builds
// against the working tree rather than a published CE version.
replace github.com/phigate/phigate => ../
