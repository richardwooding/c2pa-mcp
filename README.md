# c2pa-mcp

[![CI](https://github.com/richardwooding/c2pa-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/c2pa-mcp/actions/workflows/ci.yml)
[![Release](https://github.com/richardwooding/c2pa-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/richardwooding/c2pa-mcp/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/c2pa-mcp.svg)](https://pkg.go.dev/github.com/richardwooding/c2pa-mcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/c2pa-mcp)](https://goreportcard.com/report/github.com/richardwooding/c2pa-mcp)
[![Latest release](https://img.shields.io/github/v/release/richardwooding/c2pa-mcp?sort=semver)](https://github.com/richardwooding/c2pa-mcp/releases)
[![License: MIT](https://img.shields.io/github/license/richardwooding/c2pa-mcp)](LICENSE)

A CLI **and** [Model Context Protocol](https://modelcontextprotocol.io) server for reading
and validating [C2PA / Content Credentials](https://c2pa.org) provenance in **JPEG and PNG**
files. It is a thin, pure-Go wrapper around
[`github.com/richardwooding/c2pa`](https://github.com/richardwooding/c2pa) — that library does
all the C2PA work; this repo just exposes it to humans (CLI) and to AI agents (MCP).

![c2pa-mcp detect and verify in the terminal](docs/demo.gif)

Two operations, mirroring the library's two modes:

- **detect** — report what a file *claims* about its provenance (generator, title, AI flag,
  claimed signer and signing time). Fast and **UNVERIFIED**, like reading EXIF. No crypto.
- **verify** — fully validate the manifest: COSE signature, certificate chain against the trust
  list, assertion and hard-binding hashes, and the RFC 3161 timestamp. Returns an overall
  `valid` flag plus per-step C2PA status codes.

## Install

Homebrew (via the [richardwooding/homebrew-tap](https://github.com/richardwooding/homebrew-tap) tap):

```sh
brew install richardwooding/tap/c2pa-mcp
```

Container image (GitHub Container Registry):

```sh
docker pull ghcr.io/richardwooding/c2pa-mcp:latest
docker run --rm ghcr.io/richardwooding/c2pa-mcp:latest --version
# serve over HTTP from a container:
docker run --rm -p 8080:8080 ghcr.io/richardwooding/c2pa-mcp:latest \
  serve --transport http --http-addr :8080
```

From source:

```sh
go install github.com/richardwooding/c2pa-mcp@latest
```

Requires Go 1.26+ to build.

## CLI usage

```sh
# Detect (human-readable; reads stdin when given "-")
c2pa-mcp detect image.jpg
cat image.png | c2pa-mcp detect -

# Detect as JSON
c2pa-mcp detect image.jpg --json

# Verify — exits non-zero (1) when the manifest is NOT valid, for scripting
c2pa-mcp verify image.jpg
c2pa-mcp verify image.jpg --json

# Verify with custom trust anchors / options
c2pa-mcp verify image.jpg \
  --signing-trust   my-signing-roots.pem \
  --timestamp-trust my-tsa-roots.pem \
  --online-revocation \
  --max-scan 33554432
```

The CLI auto-detects JPEG vs PNG from the file's magic bytes; other formats are rejected.

## MCP server usage

Run the server with `c2pa-mcp serve`. Two transports are supported:

### stdio (local agents / editors)

```sh
c2pa-mcp serve                 # transport defaults to stdio
c2pa-mcp serve --transport stdio
```

Example client config (Claude Desktop / Claude Code style):

```json
{
  "mcpServers": {
    "c2pa": {
      "command": "c2pa-mcp",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
```

### Streamable HTTP (networked deployments)

```sh
c2pa-mcp serve --transport http --http-addr :8080 --http-path /mcp
```

This serves the modern MCP **Streamable HTTP** transport (protocol 2025-06-18), which uses SSE
internally for streaming responses. The deprecated standalone SSE transport is intentionally not
provided.

### Tools

Both tools accept exactly one of `path`, `url`, or `bytes` (base64):

| Tool     | Arguments | Returns |
|----------|-----------|---------|
| `detect` | `path` \| `url` \| `bytes` | text summary + structured `DetectResult` |
| `verify` | `path` \| `url` \| `bytes`, plus optional `online_revocation` (bool), `max_scan` (int) | text summary + structured `VerifyResult` |

`path` is read from the server's local filesystem (best for stdio servers); `url` is fetched by
the server; `bytes` carries the image inline (best for remote HTTP servers). Each tool returns a
human-readable text block **and** a structured-content JSON payload. An unreadable input
(missing file, bad base64, unsupported format) is a tool error; an *invalid manifest* is a
normal `verify` result with `valid: false`.

## Result shapes

`detect` →

```json
{
  "present": true,
  "claim_generator": "make_test_images/0.33.1 c2pa-rs/0.33.1",
  "title": "CA.jpg",
  "format": "image/jpeg",
  "ai_generated": false,
  "signed_by": "C2PA Signer",
  "signed_at": "2024-08-06T21:53:37Z"
}
```

`verify` adds `valid`, `active_manifest_label`, a verified `signed_at`, the `signers` chain
(subject CNs, leaf first), and an ordered `statuses` list of `{code, severity, uri, explanation}`
entries using the C2PA §15 status codes.

## Development

```sh
go test ./...                      # unit + in-memory MCP round-trip tests
go test -race -timeout 120s ./...  # what CI runs
go vet ./...
golangci-lint run
go fix -diff ./...                 # should print nothing (run go fix ./... if it does)
```

[`go fix`](https://go.dev/blog/gofix) is the rewritten Go 1.26+ modernizer; CI fails if it would
change anything.

### Releasing

Releases are automated with [GoReleaser](https://goreleaser.com) and
[ko](https://ko.build), triggered by pushing a `vX.Y.Z` tag. The
`.github/workflows/release.yml` workflow builds cross-platform binaries, publishes a GitHub
Release with archives + checksums, builds and pushes a multi-arch OCI image to
`ghcr.io/richardwooding/c2pa-mcp` (ko, with an SPDX SBOM), and updates the Homebrew cask in
[richardwooding/homebrew-tap](https://github.com/richardwooding/homebrew-tap).

The workflow needs a `HOMEBREW_TAP_GITHUB_TOKEN` repository secret — a token with `contents:write`
on the tap repo. The container push uses the built-in `GITHUB_TOKEN`.

```sh
# verify locally before tagging:
go test ./... && go fix -diff ./...
goreleaser release --snapshot --clean    # dry run, no publish
go tool gorelease -base=<previous tag>   # API-compat / semver sanity check

# cut a release:
git tag vX.Y.Z && git push origin vX.Y.Z
```

The module also pins [`gorelease`](https://pkg.go.dev/golang.org/x/exp/cmd/gorelease) as a tool
dependency (`go tool gorelease`) for semantic-version / API-compatibility checks.

## License

MIT — see [LICENSE](LICENSE). The test fixture under `testdata/` is from contentauth/c2pa-rs;
see [testdata/README.md](testdata/README.md) for its provenance and license.
