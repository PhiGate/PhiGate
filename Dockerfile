# PhiGate container image.
#
# tree-sitter requires cgo, which is the single biggest adoption barrier the
# project has: "you need Go 1.26 and a working C toolchain" stops evaluation
# before it starts in most enterprise environments. This image removes that
# barrier — the result is a static binary on a distroless base with no shell,
# no package manager, and nothing else to audit.

# ---------- build ----------
FROM golang:1.27-bookworm AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download modules.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static linking so the binary runs on a distroless base. cgo stays on because
# tree-sitter needs it; the C parts are linked statically too.
ENV CGO_ENABLED=1 GOOS=linux
RUN go build -trimpath \
      -ldflags "-s -w -extldflags '-static'" \
      -tags osusergo,netgo \
      -o /out/phigate ./cmd/phigate \
 && go build -trimpath \
      -ldflags "-s -w -extldflags '-static'" \
      -tags osusergo,netgo \
      -o /out/phigate-eval ./cmd/phigate-eval

# Fail the build if the test suite fails: the leak corpus and the guard tests
# are the product's guarantees, and an image must not ship without them passing.
RUN go test ./...

# ---------- runtime ----------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/phigate /usr/local/bin/phigate
COPY --from=build /out/phigate-eval /usr/local/bin/phigate-eval

USER nonroot:nonroot
EXPOSE 8080

# Liveness only. Readiness (/readyz) probes the upstream backends and belongs in
# the orchestrator, where a slow probe does not block container start.
#
# The image has no shell and no curl, so the binary probes itself: -healthcheck
# issues a real GET to /healthz and exits non-zero on failure. Running something
# cheap and local instead would report healthy with the HTTP server wedged,
# which is the one failure a health check exists to catch.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/phigate", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/phigate"]
