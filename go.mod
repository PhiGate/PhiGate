module github.com/phigate/phigate

// Go 1.26 is a floor, not a preference. PhiGate terminates TLS on its listener
// and initiates TLS to upstream providers, so it is directly exposed to the
// standard library's TLS, net/http and crypto/x509 issues. Toolchains before
// 1.25.12 ship a stdlib with 25 known vulnerabilities that govulncheck flags
// against this code, including an unauthenticated TLS 1.3 KeyUpdate DoS on the
// listener and html/template XSS reachable from the dashboard.

go 1.26.0

require (
	github.com/tree-sitter/go-tree-sitter v0.25.0
	github.com/tree-sitter/tree-sitter-go v0.25.0
	github.com/tree-sitter/tree-sitter-python v0.25.0
)

require github.com/mattn/go-pointer v0.0.1 // indirect
