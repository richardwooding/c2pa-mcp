# c2pa-mcp

[![CI](https://github.com/richardwooding/c2pa-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/c2pa-mcp/actions/workflows/ci.yml)
[![Release](https://github.com/richardwooding/c2pa-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/richardwooding/c2pa-mcp/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/c2pa-mcp.svg)](https://pkg.go.dev/github.com/richardwooding/c2pa-mcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/c2pa-mcp)](https://goreportcard.com/report/github.com/richardwooding/c2pa-mcp)
[![Latest release](https://img.shields.io/github/v/release/richardwooding/c2pa-mcp?sort=semver)](https://github.com/richardwooding/c2pa-mcp/releases)
[![License: MIT](https://img.shields.io/github/license/richardwooding/c2pa-mcp)](LICENSE)

A CLI **and** [Model Context Protocol](https://modelcontextprotocol.io) server for reading,
validating and signing [C2PA / Content Credentials](https://c2pa.org) provenance in **JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF**
files. It is a thin, pure-Go wrapper around
[`github.com/richardwooding/c2pa`](https://github.com/richardwooding/c2pa) — that library does
all the C2PA work; this repo just exposes it to humans (CLI) and to AI agents (MCP).

![c2pa-mcp detect and verify in the terminal](docs/demo.gif)

Three operations, mirroring the library's three modes:

- **detect** — report what a file *claims* about its provenance (generator, title, AI flag,
  claimed signer and signing time). Fast and **UNVERIFIED**, like reading EXIF. No crypto.
- **verify** — fully validate the manifest: COSE signature, certificate chain against the trust
  list, assertion and hard-binding hashes, and the RFC 3161 timestamp. Returns an overall
  `valid` flag plus per-step C2PA status codes.
- **sign** — embed a signed manifest with your own key and certificate chain, into any of the
  supported formats. An asset that already carries Content Credentials keeps them, chained as
  the new manifest's parent. Nothing is written unless the output validates. Optionally also
  writes a [soft binding](#soft-bindings) — an identifier computed from the content, which
  survives the re-encoding that breaks a hash.

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
# sign, with the key and certificate mounted read-only:
docker run --rm -v "$PWD:/work" -v "$PWD/signer.key:/run/secrets/key:ro" -v "$PWD/signer.crt:/run/secrets/crt:ro" \
  ghcr.io/richardwooding/c2pa-mcp:latest \
  sign /work/photo.jpg /work/photo-signed.jpg --signing-key /run/secrets/key --signing-cert /run/secrets/crt
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

The CLI auto-detects the container from the file's magic bytes (%PDF- may appear anywhere in the first 1 KiB); other formats are rejected.

```sh
# Sign — needs an unencrypted PEM key and the certificate chain, leaf first
c2pa-mcp sign photo.jpg photo-signed.jpg \
  --signing-key signer.key --signing-cert signer.crt \
  --title "photo.jpg" --digital-source-type digitalCapture

# Re-sign an asset that already has Content Credentials: the existing manifest
# is kept as the new one's parentOf ingredient (action defaults to "opened")
c2pa-mcp sign signed.jpg edited.jpg --signing-key signer.key --signing-cert signer.crt

# Stream: stdin to stdout, summary on stderr; --force overwrites an existing output
cat photo.jpg | c2pa-mcp sign - - --signing-key signer.key --signing-cert signer.crt > out.jpg
c2pa-mcp sign photo.jpg photo.jpg --force --signing-key signer.key --signing-cert signer.crt  # in place

# Timestamp every signature with an RFC 3161 authority
c2pa-mcp sign photo.jpg out.jpg --signing-key signer.key --signing-cert signer.crt \
  --tsa https://timestamp.digicert.com

# Also write a soft binding: an ISO 24138 ISCC Image-Code computed from the
# pixels, so a re-encoded copy can still be matched back to this manifest
c2pa-mcp sign photo.jpg out.jpg --signing-key signer.key --signing-cert signer.crt \
  --soft-binding iscc
```

`--signing-key`, `--signing-cert` and `--tsa` also read `C2PA_SIGNING_KEY`, `C2PA_SIGNING_CERT`
and `C2PA_TSA_URL` (file paths and a URL). See [Signing](#signing) for keys and what verifiers say.

## MCP server usage

Run the server with `c2pa-mcp serve`. Two transports are supported:

### stdio (local agents / editors)

```sh
c2pa-mcp serve                 # transport defaults to stdio
c2pa-mcp serve --transport stdio

# with a signing identity, the server also offers the sign tool
c2pa-mcp serve --signing-key signer.key --signing-cert signer.crt [--tsa URL]
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

Every tool accepts exactly one of `path`, `url`, or `bytes` (base64):

| Tool     | Arguments | Returns |
|----------|-----------|---------|
| `detect` | `path` \| `url` \| `bytes` | text summary + structured `DetectResult` |
| `verify` | `path` \| `url` \| `bytes`, plus optional `online_revocation` (bool), `max_scan` (int) | text summary + structured `VerifyResult` |
| `sign`   | `path` \| `url` \| `bytes`, `output` (path; required unless the input is `bytes`), optional `overwrite` (bool), `title`, `action` (`created` \| `opened`), `digital_source_type`, `soft_binding` (`iscc`) | text summary + structured `SignResult` (with `signed_bytes` when no `output`) |

`sign` exists only when the server was started with `--signing-key` and `--signing-cert`; the key
is the **operator's**, configured at startup, never a tool argument. Anyone who can reach the
server can then produce signatures with it — keep an HTTP-transport server with a signing identity
behind authentication. The tool refuses to overwrite an existing `output` unless `overwrite` is
true, and writes through a temporary file, so a failed sign never damages a file that was there.

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
  "attribution": "asset",
  "claim_generator": "make_test_images/0.33.1 c2pa-rs/0.33.1",
  "title": "CA.jpg",
  "format": "image/jpeg",
  "ai_generated": false,
  "signed_by": "C2PA Signer",
  "signed_at": "2024-08-06T21:53:37Z"
}
```

`attribution` says who the manifest is a claim **about**: `asset` when the file's own structure
associates it, `embedded` when the file associates it with something it *carries* (a PDF
object-level manifest, spec §A.4.3), `unknown` when nothing places it at all. For the latter two,
`signed_by` belongs to the resource the manifest describes rather than to the file — do not report
it as the file's signer.

`verify` adds `valid`, `active_manifest_label`, a verified `signed_at`, the `signers` chain
(subject CNs, leaf first), `binding`, any `soft_bindings` (see [below](#soft-bindings)), and an
ordered `statuses` list of `{code, severity, uri, explanation}` entries using the C2PA §15 status
codes.

`binding` answers a different question from `valid`: were **these bytes** the ones that were signed?

| `binding` | meaning |
| --- | --- |
| `verified` | a hard binding covered these bytes and held |
| `failed` | a hard binding covered these bytes and did not hold |
| `unevaluated` | a hard binding exists, and this call did not check it against these bytes — a PDF manifest attached to an embedded object (§A.4.3), an asset past the scan cap, a fragmented asset without its fragments |
| `none` | nothing bound the asset: no manifest, or no usable hard binding |

The two come apart in both directions, which is why both are reported. The fixture in `testdata`
is `valid: false` (its test PKI is not in the production trust list) with `binding: verified` — the
bytes really are the ones that manifest signed. A PDF whose manifest hangs off an embedded object is
`valid: true` with `binding: unevaluated` — nothing hashed the document. `unevaluated` is not a
weaker pass; it means ask a different question, or supply the fragments.

`sign` →

```json
{
  "container": "jpeg",
  "action": "c2pa.created",
  "chained_prior_manifest": false,
  "timestamped": false,
  "soft_binding": "ISCC:EEA4GQZQTY6J5DTH",
  "size": 118204,
  "output": "photo-signed.jpg",
  "verify": { "valid": true, "binding": "verified", "verified_signer": "My Signer", "...": "a VerifyResult" }
}
```

`action` is the first action written; `chained_prior_manifest` says the asset already carried a
manifest, now the new one's `parentOf` ingredient; `soft_binding` is the identifier written when one
was asked for; `verify` is the library's verdict on the
**output**, anchored at the signing chain's own top certificate and without descending into a prior
manifest — the library refuses to write anything that fails this check, so `valid` is
confirmation. Run `verify` on the file for the full picture, including how a prior manifest fares
against the trust list.

## Soft bindings

A hard binding is a hash of the bytes, so it dies the moment a platform re-encodes an image or
strips its metadata — the standard criticism of C2PA, and the spec's own answer is the
`c2pa.soft-binding` assertion (§18.10): an identifier computed from the **content**, so a stripped
or re-encoded copy can still be matched back to its manifest through a provenance store (§9.3.1).

```sh
c2pa-mcp sign photo.jpg out.jpg --signing-key signer.key --signing-cert signer.crt --soft-binding iscc
#   Soft binding written: ISCC:EEA4GQZQTY6J5DTH
```

`iscc` computes an **ISO 24138 Image-Code**, registered on the [C2PA soft binding algorithm
list](https://github.com/c2pa-org/softbinding-algorithm-list) as `io.iscc.v0` — the one open,
general-purpose fingerprint on it. The normalisation the standard assumes (EXIF transpose, flatten
onto white, trim the border, greyscale, resample to 32×32) comes from
[`fingerprint`](https://github.com/richardwooding/fingerprint) and the code itself from
[`iscc-lib`](https://github.com/iscc/iscc-lib), the official pure-Go implementation. Both stay out
of the `c2pa` library on purpose: it implements no soft binding algorithm, so that it works with
every algorithm on the list — including the 44 proprietary watermarks, which you can still write by
handing the library your vendor's value.

What it is worth is visible in the test suite: the same image as PNG, as JPEG at default quality,
as JPEG at quality 40 and as a palette GIF all produce the **same** `ISCC:` code, while every one of
those files has a different hard binding.

Four things to know:

- **JPEG, PNG and GIF only.** WebP, TIFF, HEIC, AVIF, MP4, MP3, SVG and PDF sign as usual but
  `--soft-binding iscc` refuses them, because this build cannot decode them to pixels and a code
  computed from the wrong pixels is silently wrong rather than an error.
- **The hard binding is still written.** §9.1 forbids a soft binding from being an asset's only
  content binding, so this adds one; it never substitutes.
- **The assertion carries the code's raw digest**, with the canonical `ISCC:…` string in the
  assertion's `name`. That split is a decision, not a rule — the spec says only "algorithm specific
  format" and the registry entry for `io.iscc.v0` defines none. The reasoning is written down in the
  [`c2pa` library's README](https://github.com/richardwooding/c2pa#signing), and it is unverified
  against any third-party resolver, there being none to verify against.
- **Verifiers report a soft binding; they do not check it.** `verify` lists them under
  `soft_bindings` with the algorithm, whether it is on the embedded copy of the C2PA list, and the
  value — and says `REPORTED not verified`, because matching one means recomputing it and comparing
  within a *tolerance*, and a tolerance is a policy rather than a fact. c2pa-rs's `c2patool` does
  the same: it prints the assertion and its verdict is unchanged either way. A soft binding is a
  lead to follow, never evidence on its own.

## Signing

`sign` needs a private key (unencrypted PEM: PKCS#8 `PRIVATE KEY`, `EC PRIVATE KEY` or
`RSA PRIVATE KEY`) and its certificate chain (PEM, leaf first; the root may be omitted). Both may
sit in one file. The COSE algorithm follows the key: P-256/384/521 → ES256/384/512, RSA ≥ 2048 →
PS256, Ed25519 → EdDSA. The certificate must satisfy the C2PA profile: `digitalSignature` key
usage, a constrained EKU such as `emailProtection`, not a CA. A self-signed one for testing:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout signer.key -out signer.crt -subj "/CN=My Signer/O=Example" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=emailProtection" \
  -addext "basicConstraints=critical,CA:FALSE"
```

What verifiers then say: `c2pa-mcp verify photo-signed.jpg` reports `signingCredential.untrusted`
until you pass `--signing-trust signer.crt` (or the CA's root), because a private chain is not on
the C2PA trust list; c2pa-rs's `c2patool` behaves the same way — `Valid` with a private chain,
`Trusted` with `trust --trust_anchors signer.crt`. To be trusted by the world, sign with a chain
issued by a CA on the [C2PA trust list](https://github.com/c2pa-org/conformance-public).

Signing is the one operation that can touch the network: only with `--tsa`, when every signature is
timestamped by that RFC 3161 authority and the token is embedded after being verified. A TSA failure
fails the sign and writes nothing. Fragmented MP4, encrypted or certified PDFs and ID3v2.2 MP3 tags
are refused by the library; see its README for the full list.

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

## Sponsor

If this saves you time, you can [sponsor its maintenance](https://github.com/sponsors/richardwooding).
Sponsorship pays for the unglamorous half — triage, dependency bumps, release plumbing — and is
never a condition of getting help here.

## License

MIT — see [LICENSE](LICENSE). The test fixture under `testdata/` is from contentauth/c2pa-rs;
see [testdata/README.md](testdata/README.md) for its provenance and license.
