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

## sample.mp3

"Belly Button", 15.5 seconds, copied **verbatim** from
[iscc/iscc-samples](https://github.com/iscc/iscc-samples)
(`iscc_samples/files/audio/demo.mp3`) by Titusz Pan, **CC-BY-4.0** — the same collection and licence
as the image fixtures the `fingerprint` package uses.

Verbatim matters here. This is the exact file `iscc-sdk`, the reference implementation of ISO 24138,
publishes a Chromaprint vector and an ISCC for in its `tests/test_audio.py`. That makes
`ISCC:EIAWUJFCEZZOJYVD` a published number rather than a number this project computed and then
asserted against itself, and `TestSignSoftBindingMP3` fails loudly if the two ever part company.

It also exercises two things nothing else here does. The MP3 carries a 4119-byte ID3v2 tag with
cover art, and c2pa embeds an MP3 manifest in an ID3v2 GEOB frame — so signing rewrites the tag
section the file arrived with. The audio frames have to come through untouched, and the Xing header
that the gapless trimming depends on has to still be findable behind the new tag. The recompute
assertion in that test is what proves both.

No WAV fixture is committed: `synthWAV` generates one in the test, deterministically and with
integer arithmetic only, which costs nothing and keeps the repository small.
