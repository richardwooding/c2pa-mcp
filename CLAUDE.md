# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`c2pa-mcp` is both a CLI **and** an MCP server for reading and validating C2PA / Content
Credentials provenance in **JPEG, PNG, HEIC, AVIF, MP4, MOV or PDF** files. It is a thin wrapper around
[`github.com/richardwooding/c2pa`](https://github.com/richardwooding/c2pa) — that library does all
the actual C2PA work (manifest reading, COSE signatures, cert chains, hashes, RFC 3161 timestamps).
This repo only resolves an input image, sniffs its format, and re-shapes the library's output for
two front ends (humans via CLI, agents via MCP). When a change concerns C2PA semantics rather than
plumbing, the fix usually belongs upstream in the `c2pa` library, not here.

Two operations mirror the library's two modes:
- **detect** — what a file *claims* (generator, title, AI flag, claimed signer/time). Fast,
  **UNVERIFIED**, no crypto — like reading EXIF.
- **verify** — full cryptographic validation; returns an overall `valid` flag plus per-step C2PA
  §15 status codes. An *invalid manifest is a normal result* (`valid: false`), not an error.

Requires Go 1.26+.

## Commands

```sh
go test ./...                      # unit + in-memory MCP round-trip tests
go test -race -timeout 120s ./...  # what CI runs
go test ./internal/analyze/ -run TestName   # a single test
go vet ./...
golangci-lint run                  # CI installs `latest` (a v2 binary)
go fix -diff ./...                 # MUST print nothing — CI fails otherwise (run `go fix ./...` to apply)
```

`go fix` is the Go 1.26+ modernizer; CI fails if it would rewrite anything, so run it before pushing.

## Architecture

Three layers, one shared core:

- **`main.go`** — the [Kong](https://github.com/alecthomas/kong) CLI command tree (`detect`,
  `verify`, `serve`). `version`/`commit`/`date` are injected via `-ldflags` by GoReleaser. `verify`
  returns the sentinel `errInvalid` to force exit code 1 on an invalid manifest *without printing*
  an error (so scripts can branch on exit status); `main` maps it to `os.Exit(1)`.

- **`internal/analyze`** — the **shared adapter** used identically by both front ends. This is where
  most logic lives.
  - `source.go`: `Open()` resolves an `Input` (exactly one of `Path`, `URL`, `Base64`, or the
    CLI-only `Stdin`), then `sniff()`s the first 1 KiB against JPEG/PNG/ftyp/%PDF- magic to pick the
    `c2pa.Container` (the library trusts the caller to name the format). Sniffing *peeks* via a
    `bufio.Reader` — it does not consume — so the returned reader can go straight to the library.
    Streams are not buffered fully into memory (except `Base64`), to respect the validator's scan
    ceiling.
  - `analyze.go`: `Detect`/`Verify` call `c2pa.Read`/`c2pa.Validate` and convert the results into
    the JSON-serializable `DetectResult`/`VerifyResult`. `VerifyResult` embeds the unverified
    `DetectResult` for convenience. Each result type has a `Summary()` for human-readable text.
    `VerifyOptions.toValidateOptions()` translates the exposed knobs (trust PEMs, online revocation,
    max scan) into `c2pa.ValidateOption`s.

- **`internal/mcpserver`** — wraps `analyze` as MCP tools using
  [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk).
  `New()` builds the server and registers the `detect`/`verify` tools; handlers in `tools.go` return
  both a text block (`Summary()`) and structured content (the result struct). `serve` runs the same
  server value over either `StdioTransport` or the **Streamable HTTP** transport (the deprecated
  standalone SSE transport is intentionally not provided).

Key invariant: the CLI and MCP server must behave identically — they share `analyze.Open`,
`analyze.Detect`, and `analyze.Verify`. Add new analysis behavior in `analyze`, then expose it from
both `main.go` and `mcpserver`.

## Releasing

Releases are automated via GoReleaser + [ko](https://ko.build), triggered by pushing a `vX.Y.Z` tag
(see `.github/workflows/release.yml`). It builds cross-platform binaries, a multi-arch OCI image
(`ghcr.io/richardwooding/c2pa-mcp`) with an SBOM, and updates the Homebrew tap. Needs a
`HOMEBREW_TAP_GITHUB_TOKEN` repo secret. Before tagging:

```sh
go test ./... && go fix -diff ./...
goreleaser release --snapshot --clean    # dry run, no publish
go tool gorelease -base=<previous tag>   # API-compat / semver sanity check (gorelease is a pinned tool dep)
```
