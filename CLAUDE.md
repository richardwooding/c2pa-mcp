# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`c2pa-mcp` is both a CLI **and** an MCP server for reading, validating and signing C2PA / Content
Credentials provenance in **JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF** files. It is a thin wrapper around
[`github.com/richardwooding/c2pa`](https://github.com/richardwooding/c2pa) — that library does all
the actual C2PA work (manifest reading, COSE signatures, cert chains, hashes, RFC 3161 timestamps).
This repo only resolves an input image, sniffs its format, loads a signing identity from PEM, and
re-shapes the library's output for two front ends (humans via CLI, agents via MCP). When a change
concerns C2PA semantics rather than plumbing, the fix usually belongs upstream in the `c2pa`
library, not here.

Three operations mirror the library's three modes:
- **detect** — what a file *claims* (generator, title, AI flag, claimed signer/time). Fast,
  **UNVERIFIED**, no crypto — like reading EXIF.
- **verify** — full cryptographic validation; returns an overall `valid` flag plus per-step C2PA
  §15 status codes. An *invalid manifest is a normal result* (`valid: false`), not an error.
  It also returns `binding` (`verified`/`failed`/`unevaluated`/`none`, from
  `c2pa.ValidationResult.Binding`), which answers the separate question "were THESE bytes the signed
  ones" — `valid` and `binding` come apart in both directions, and neither implies the other.
- **sign** — embed a signed `c2pa.claim.v2` manifest with the operator's key and chain. The
  library validates its own output before writing a byte, so a sign either produces a file that
  verifies or produces nothing; a failure IS an error (exit 1 / tool error), unlike an invalid
  manifest under verify. `--soft-binding iscc` / `soft_binding: "iscc"` ALSO writes a
  `c2pa.soft-binding` assertion over a JPEG, PNG, GIF, WebP or TIFF (see the soft-binding notes
  below); the hard binding is unaffected.

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
  `verify`, `sign`, `serve`). `version`/`commit`/`date` are injected via `-ldflags` by GoReleaser.
  `verify` returns the sentinel `errInvalid` to force exit code 1 on an invalid manifest *without
  printing* an error (so scripts can branch on exit status); `main` maps it to `os.Exit(1)`.
  `SignerFlags` (`--signing-key`, `--signing-cert`, `--tsa`, `--claim-generator`; env
  `C2PA_SIGNING_KEY` / `C2PA_SIGNING_CERT` / `C2PA_TSA_URL`, all FILE PATHS) is `embed`ded in both
  `sign` (required, checked in `load()`) and `serve` (optional — present means the MCP server gets
  the `sign` tool). The names are deliberately not `--key`/`--cert`, which on `serve` would read as
  TLS. `sign in out` writes through `analyze.SignToFile`; `sign in -` streams the asset to stdout
  and the summary to stderr. `version` is passed as the claim generator's version.

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
    max scan) into `c2pa.ValidateOption`s; `verifyWith` is the shaping step both `Verify` and
    `Sign` go through, so a signed asset is reported exactly as verify would report it.
    `VerifyResult.Binding` is `c2pa.ValidationResult.Binding.String()` — passed through, never
    derived from `Statuses`, because the library records it at the decision point (an update
    manifest's binding statuses carry the PARENT manifest's label, and `general.unsupported` is
    used for several unrelated things, so no reading of the status list reconstructs it).
    `bindingSummary` is the only place that editorialises: it spells out `unevaluated`, the state a
    reader guesses wrong. `VerifyResult.SoftBindings` is shaped by `toSoftBindingReports`
    (`softbinding.go`) — reported, never checked, and the summary line says so in as many words.
  - `sign.go`: `LoadSigner(SignerConfig)` parses PEM (PKCS#8 / SEC 1 / PKCS#1 keys, any number of
    CERTIFICATE blocks, other blocks skipped so one combined file works; an encrypted key is named
    as such with the openssl remedy) and builds a `c2pa.Signer` — which checks key↔leaf, chain
    links, validity and the C2PA profile up front, so a `Signer` that loads can only fail on an
    asset. **Errors never carry key material**: they quote the block type and the parser's message,
    and `TestLoadSigner` asserts no PEM text leaks. `(*Signer).Sign` buffers the asset (the library
    needs it whole anyway), decides `auto` action from `c2pa.Read(...).Present`, signs, then
    re-validates the output with `WithSigningTrust(own chain top)`, `WithMaxIngredientDepth(0)`,
    `WithOnlineRevocation(false)` for the `SignResult.Verify` report — depth 0 because a foreign
    prior manifest's untrusted signer or TSA would otherwise fail OUR output's report (the library
    makes the same choice for its self-check); the report says so, and points at verify.
    `SignToFile` writes through a temp file in the target directory and renames into place, so a
    failed sign never truncates an existing file and signing a file onto itself works; an existing
    path is `ErrOutputExists` unless overwrite is set.
  - `softbinding.go`: the ONE thing this repo computes rather than adapts. The `c2pa` library
    implements no soft binding algorithm by design (it takes the value from its caller, so every
    algorithm on the C2PA list works, watermarks included), so `softBindingFor` is the other half of
    that arrangement for `io.iscc.v0` — ISO 24138 — via `fingerprint.ISCCPixelsFromReader` (the
    normalisation, which is Pillow's arithmetic reproduced in Go) and `iscc-lib` (the code). What to
    know before touching it:
      - **The gate cannot be a map keyed on `c2pa.Container`**, which is what it was until WebP
        and TIFF arrived. A Container names a CARRIER, not a media type: `c2pa.RIFF` is WebP *and*
        WAV *and* AVI, `c2pa.TIFF` is TIFF and BigTIFF and DNG, `c2pa.BMFF` is MP4 alongside
        HEIC/AVIF. The c2pa library parses the RIFF form type (`riff.go`) but keeps it private, and
        nothing it exports says "this is a WebP" — `Info.Format` is producer-declared and empty
        before signing. So `isccDecodable(container, data)` reads the form type itself at offset 8,
        the way `file-search-on`'s `imagetype.go` does. TIFF passes on the container alone
        deliberately: `fingerprint` refuses a DNG, a planar file or BigTIFF WITH A REASON, which is
        more use than anything four bytes could say here.
      - Adding a format means adding a decoder in `fingerprint` AND satisfying yourself that it
        agrees with Pillow's, which is what conformance rests on — see that repo's CLAUDE.md for
        the "exactness follows the codec, not the container" argument the tests are built on.
      - **The value is the raw ISCC-UNIT digest; the canonical `ISCC:…` string goes in `name`.**
        A documented CHOICE — the spec says only "algorithm specific format" and the registry entry
        defines none. The reasoning lives in the `c2pa` library's CLAUDE.md; this function and that
        note are the two places to change if evidence ever settles it. Unverified against any
        third-party resolver.
      - **64 bits is not a flag.** Two producers who pick different widths cannot compare codes,
        which is the only thing a soft binding is for.
      - **It is computed from the asset AS IT ARRIVED**, before any manifest is embedded — and
        `TestSoftBindingRecomputableFromSignedAsset` pins that recomputing over the SIGNED file
        gives the same code back, which is the property the whole feature exists for.
      - **The report has no `Matched` and no `Valid`.** `SoftBindingReport.WellFormed` is about
        structure alone; the deprecated `url` is reported and NEVER fetched (a manifest-controlled
        outbound request is an SSRF). The library's position is report-don't-verify, because a
        tolerance is policy rather than fact, and this repo must not quietly upgrade it.

- **`internal/mcpserver`** — wraps `analyze` as MCP tools using
  [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk).
  `New(version, opts...)` builds the server and registers the `detect`/`verify` tools, and `sign`
  ONLY when `WithSigner` was given — a client should not see a capability the server cannot honour,
  and key material is configured by the operator at startup, never taken as a tool argument (an
  agent, or anyone reaching an HTTP server, would otherwise be handed the key). Handlers in
  `tools.go` return both a text block (`Summary()`) and structured content (the result struct). The
  `sign` tool requires `output` for `path`/`url` inputs (it will not guess a filename) and returns
  `signed_bytes` only for a `bytes` input without `output`; `overwrite` defaults to refuse. `serve`
  runs the same server value over either `StdioTransport` or the **Streamable HTTP** transport
  (the deprecated standalone SSE transport is intentionally not provided).

- **`internal/testpki`** — mints a self-signed P-256 certificate that satisfies the C2PA profile,
  as PEM, for tests in both packages. Imported only by tests, so it is not in the binary.

Key invariant: the CLI and MCP server must behave identically — they share `analyze.Open`,
`analyze.Detect`, `analyze.Verify`, and `analyze.Signer` (`Sign` / `SignToFile`). Add new
behavior in `analyze`, then expose it from both `main.go` and `mcpserver`. Unsigned test assets are
encoded in-memory with `image/jpeg` / `image/png`; the only fixture is the signed c2pa-rs JPEG,
which the signing tests re-sign (auto → `opened`, prior manifest chained). The soft-binding tests
need an image with real structure — `isccScene`, 96x96 — because the 16x16 gradient the other tests
use normalises to something a re-encode can move; they assert a Hamming BOUND (4 of 64 bits) and log
the actual distance, which was 0 across JPEG q75, JPEG q40, a palette GIF and TIFF when written.
**WebP is the one format needing a checked-in fixture** (`testdata/sample.webp`): Go can decode a
WebP but not write one, so it cannot be synthesised like the others. Its test earns its keep — c2pa's
RIFF embedder SYNTHESISES a VP8X chunk for a simple-format WebP, restructuring the container around
the bitstream, and `TestSignSoftBindingWebP` recomputes the code from the SIGNED file to prove that
did not move a pixel. A DNG for the refusal test is built by splicing a `DNGVersion` entry into a
`tiff.Encode` output (`withTIFFTag`, which also shifts the value offsets past the insertion) rather
than by vendoring a camera raw.

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
