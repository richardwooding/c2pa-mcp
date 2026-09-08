# testdata

## c2pa_signed.jpg

A real C2PA-signed JPEG used as the test fixture. It is `CA.jpg` from the
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs) project's test
assets (`sdk/tests/fixtures/`), licensed under Apache-2.0 / MIT (the c2pa-rs
dual license). Copied verbatim from the `github.com/richardwooding/c2pa`
library's own test corpus.

It carries a manifest with claim_generator `make_test_images/0.33.1
c2pa-rs/0.33.1`, title `CA.jpg`, a COSE_Sign1 signature whose leaf certificate
subject CN is `C2PA Signer`, and an RFC 3161 timestamp of
`2024-08-06T21:53:37Z`. It is an *edited* image, not AI-generated.

It is signed by the c2pa-rs **test** PKI, so full verification only succeeds
when anchored at the fixture's own signer chain — the library's tests do this
with `WithSigningTrust`. The `verify` path here uses the embedded production
C2PA trust list by default, so this fixture is expected to report
`signingCredential.untrusted` (a failure) unless a matching trust pool is
supplied. Tests assert the *structure* of the result accordingly.

## sample.webp

A 5 KB lossy WebP (simple format, one `VP8 ` chunk) of the 200×133 photograph from
[iscc/iscc-samples](https://github.com/iscc/iscc-samples), by Titusz Pan, **CC-BY-4.0** — the same
image the `fingerprint` module uses as its ISCC oracle, encoded to WebP with libwebp 1.6.0 via
sharp. A derivative of a CC-BY-4.0 work.

It is checked in because **Go can decode a WebP but not write one**, so unlike the JPEG, PNG, GIF and
TIFF assets in these tests it cannot be synthesised in memory. It exists to prove one thing that
nothing else can: c2pa's RIFF embedder synthesises a `VP8X` chunk when signing a simple-format WebP,
restructuring the container around the bitstream, and the ISCC recomputed from the *signed* file must
still equal the one in its own assertion — otherwise a resolver would never match it.
