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
