package analyze

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	iscc "github.com/iscc/iscc-lib/packages/go"
	"github.com/richardwooding/c2pa"
	"github.com/richardwooding/fingerprint"
)

// Soft bindings — perceptual identifiers that survive what a hard binding
// cannot.
//
// A hard binding is a hash of the bytes, so it dies the moment a platform
// re-encodes an asset or strips its metadata. A soft binding (C2PA §18.10) is
// the spec's answer: an identifier computed from the CONTENT, so a stripped or
// re-encoded copy can still be matched back to its manifest through a
// provenance store (§9.3.1). It never replaces the hard binding — §9.1 forbids
// a soft binding from being an asset's only content binding, and every asset
// signed here still gets the hard one.
//
// The c2pa library computes no soft binding algorithm on purpose: it takes the
// value from its caller, so that it stays dependency-free and works with every
// algorithm on the C2PA list, including the 44 proprietary watermarks nobody
// outside their vendors could implement. This file is the other half of that
// arrangement for the one algorithm with both an open standard and a pure-Go
// implementation.
const (
	// SoftBindingNone writes no soft binding, and is the default.
	SoftBindingNone = "none"
	// SoftBindingISCC computes an ISCC Image-Code (ISO 24138), registered on
	// the C2PA soft binding algorithm list as io.iscc.v0 — the one open,
	// general-purpose fingerprint on it. JPEG, PNG, GIF, WebP and TIFF.
	SoftBindingISCC = "iscc"
)

// isccAlgorithm is the registry identifier written into the assertion's "alg",
// and is also accepted in place of SoftBindingISCC by callers who would rather
// name the algorithm the way the list does.
const isccAlgorithm = "io.iscc.v0"

// isccBits is the Image-Code's length in bits. 64 is the standard's default and
// what every published vector uses. It is deliberately not a flag: two
// producers who pick different widths cannot compare their codes, which is the
// only thing a soft binding is for.
const isccBits = 64

// isccDecodable reports whether an asset in this container is one this build
// can turn into pixels, given its leading bytes.
//
// The bytes are needed because a c2pa.Container names a CARRIER, not a media
// type: c2pa.RIFF is WebP *and* WAV *and* AVI, c2pa.TIFF is TIFF and BigTIFF
// and DNG, and c2pa.BMFF is MP4 alongside HEIC and AVIF. The c2pa library
// parses the RIFF form type but keeps it private, and nothing it exports says
// "this is a WebP" — Info.Format is producer-declared and empty before signing
// — so the form type is read here, at offset 8, the way file-search-on's
// imagetype.go reads it.
//
// TIFF passes on the container alone even though several TIFF layouts are
// undecodable: fingerprint refuses those WITH A REASON (a DNG, separate colour
// planes, BigTIFF), which is more useful than anything four bytes could say
// here. HEIC and AVIF have no pure-Go decoder at all, so BMFF is refused.
func isccDecodable(container c2pa.Container, data []byte) bool {
	switch container {
	case c2pa.JPEG, c2pa.PNG, c2pa.GIF, c2pa.TIFF:
		return true
	case c2pa.RIFF:
		return isWebP(data)
	default:
		return false
	}
}

// isWebP reports whether a RIFF file's form type is WEBP rather than WAVE or
// AVI. All three are the same carrier to c2pa, and only one is an image.
func isWebP(data []byte) bool {
	return len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP"
}

// isccFormatDetail names what the asset actually is, for a refusal message. A
// bare container name would tell a user with a WAV that "this asset is riff",
// which is true and useless.
func isccFormatDetail(container c2pa.Container) string {
	switch container {
	case c2pa.RIFF:
		return "a RIFF container that is not a WebP, so a WAV or an AVI"
	case c2pa.BMFF:
		return "BMFF — an MP4, or a HEIC/AVIF, which needs a decoder that does not exist in pure Go"
	default:
		return string(container)
	}
}

var (
	// ErrSoftBindingAlgorithm is returned for a soft binding algorithm this
	// tool cannot compute.
	ErrSoftBindingAlgorithm = errors.New(`soft binding must be "iscc" (ISO 24138, io.iscc.v0) or "none"`)
	// ErrSoftBindingFormat is returned when the algorithm is one this tool can
	// compute but the asset is not one it can compute it over.
	ErrSoftBindingFormat = errors.New("an ISCC Image-Code needs a still image this build can decode: JPEG, PNG, GIF, WebP or TIFF")
)

// softBindingFor computes the soft binding named by alg over the asset bytes,
// returning (nil, "", nil) when none was asked for. The second result is the
// algorithm's canonical identifier for the caller to report — for ISCC, the
// "ISCC:…" string.
//
// What goes in the assertion is the RAW ISCC-UNIT DIGEST, with the canonical
// ISCC string in the assertion's "name". That split is a decision, not a rule:
// the spec says only "algorithm specific format" and the registry entry for
// io.iscc.v0 defines none. The reasoning is recorded in the c2pa library's
// README and CLAUDE.md, alongside the fact that it is unverified against any
// third-party resolver, there being none to verify against. If evidence ever
// says otherwise, this function and that note are the two places to change.
func softBindingFor(alg string, container c2pa.Container, data []byte) (*c2pa.SoftBindingInfo, string, error) {
	switch alg {
	case "", SoftBindingNone:
		return nil, "", nil
	case SoftBindingISCC, isccAlgorithm:
		// below
	default:
		return nil, "", fmt.Errorf("%w: got %q", ErrSoftBindingAlgorithm, alg)
	}
	if !isccDecodable(container, data) {
		return nil, "", fmt.Errorf("%w (this asset is %s)", ErrSoftBindingFormat, isccFormatDetail(container))
	}

	// The normalisation — EXIF transpose, flatten onto white, trim the border,
	// grayscale, resample to 32x32 — is the half of ISO 24138 its conformance
	// vectors do not cover, since they start from the 1024 pixels. It is
	// Pillow's arithmetic reproduced in Go; see the fingerprint package.
	pixels, err := fingerprint.ISCCPixelsFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("normalise the image for ISCC: %w", err)
	}
	code, err := iscc.GenImageCodeV0(pixels, isccBits)
	if err != nil {
		return nil, "", fmt.Errorf("compute the ISCC Image-Code: %w", err)
	}
	dec, err := iscc.IsccDecode(code.Iscc)
	if err != nil {
		return nil, "", fmt.Errorf("decode the ISCC %q: %w", code.Iscc, err)
	}
	return &c2pa.SoftBindingInfo{
		Algorithm: isccAlgorithm,
		Name:      code.Iscc,
		Blocks:    []c2pa.SoftBindingBlockInfo{{Value: dec.Digest}},
	}, code.Iscc, nil
}

// SoftBindingReport is the JSON-serializable form of one c2pa.SoftBinding a
// verifier FOUND — not to be confused with c2pa.SoftBindingInfo, which is what
// a signer WRITES.
//
// Everything here is as presented by the manifest, except the three algorithm
// facts marked below, which come from the c2pa library's embedded snapshot of
// the C2PA soft binding algorithm list. Nothing in it is verified: checking a
// soft binding means recomputing it over the asset and comparing within a
// TOLERANCE, and a tolerance is policy rather than fact, so neither the library
// nor this tool judges one. WellFormed is about the STRUCTURE alone.
type SoftBindingReport struct {
	// Label is the assertion label ("c2pa.soft-binding", or an instance form
	// such as "c2pa.soft-binding__1" when a manifest carries several).
	Label string `json:"label"`
	// Algorithm is the resolved identifier: the assertion's own "alg", else the
	// claim's "alg_soft". A name, not a proven property of the bytes.
	Algorithm string `json:"algorithm,omitempty"`
	// AlgorithmType is "watermark" or "fingerprint" — from the embedded list,
	// empty when the algorithm is not on it.
	AlgorithmType string `json:"algorithm_type,omitempty"`
	// AlgorithmRegistered reports that the algorithm is on the embedded
	// snapshot of the C2PA list. False can mean "registered upstream since
	// this build", so it is not a verdict on the producer.
	AlgorithmRegistered bool `json:"algorithm_registered"`
	// AlgorithmFromClaim reports that the algorithm came from the claim's
	// alg_soft rather than from this assertion.
	AlgorithmFromClaim bool `json:"algorithm_from_claim,omitempty"`
	// Name is the optional human-readable name. Free text; for an ISCC written
	// by this tool it is the canonical "ISCC:…" string.
	Name string `json:"name,omitempty"`
	// URL is the assertion's optional "url", which the spec marks unused and
	// deprecated. It is reported so nothing is hidden and is NEVER fetched: a
	// manifest-controlled outbound request would be an SSRF.
	URL string `json:"url,omitempty"`
	// Blocks are the algorithm's outputs, in stored order.
	Blocks []SoftBindingBlockReport `json:"blocks,omitempty"`
	// WellFormed reports that the assertion satisfied the spec's structural
	// rules. It says nothing about whether any content matches.
	WellFormed bool `json:"well_formed"`
}

// SoftBindingBlockReport is one block of a reported soft binding.
type SoftBindingBlockReport struct {
	// Value is the block's value bytes, base64 (standard encoding) — the
	// algorithm's output, opaque to this tool.
	Value string `json:"value"`
	// TimespanStartMS and TimespanEndMS scope the block to a millisecond range
	// of a temporal asset, when it says so. As presented: the spec gives no
	// ordering rule, so an end before the start is reported, not corrected.
	TimespanStartMS *uint64 `json:"timespan_start_ms,omitempty"`
	TimespanEndMS   *uint64 `json:"timespan_end_ms,omitempty"`
	// HasRegion reports a region-of-interest scope, which the c2pa library
	// keeps as raw CBOR and does not decode, so neither does this.
	HasRegion bool `json:"has_region,omitempty"`
	// HasExtent reports the deprecated "extent" scope.
	HasExtent bool `json:"has_extent,omitempty"`
}

// toSoftBindingReports shapes the library's soft bindings for JSON.
func toSoftBindingReports(sbs []c2pa.SoftBinding) []SoftBindingReport {
	var out []SoftBindingReport
	for _, sb := range sbs {
		r := SoftBindingReport{
			Label:               sb.Label,
			Algorithm:           sb.Algorithm,
			AlgorithmType:       sb.AlgorithmType,
			AlgorithmRegistered: sb.AlgorithmRegistered,
			AlgorithmFromClaim:  sb.AlgorithmFromClaim,
			Name:                sb.Name,
			URL:                 sb.URL,
			WellFormed:          sb.WellFormed,
		}
		for _, b := range sb.Blocks {
			br := SoftBindingBlockReport{
				Value:     base64.StdEncoding.EncodeToString(b.Value),
				HasRegion: len(b.Scope.Region) > 0,
				HasExtent: len(b.Scope.Extent) > 0,
			}
			if ts := b.Scope.Timespan; ts != nil {
				start, end := ts.Start, ts.End
				br.TimespanStartMS, br.TimespanEndMS = &start, &end
			}
			r.Blocks = append(r.Blocks, br)
		}
		out = append(out, r)
	}
	return out
}

// summarize renders one soft binding as a single line. It always says that
// nothing checked it: a reader who sees an algorithm name and a code beside a
// VALID verdict will otherwise assume the content was matched.
func (r SoftBindingReport) summarize() string {
	var b bytes.Buffer
	alg := r.Algorithm
	if alg == "" {
		alg = "(no algorithm named)"
	}
	b.WriteString(alg)
	switch {
	case r.AlgorithmType != "" && r.AlgorithmRegistered:
		fmt.Fprintf(&b, " (%s, registered)", r.AlgorithmType)
	case r.AlgorithmRegistered:
		b.WriteString(" (registered)")
	default:
		b.WriteString(" (not on this build's copy of the C2PA list)")
	}
	if r.Name != "" {
		fmt.Fprintf(&b, " %s", r.Name)
	}
	if !r.WellFormed {
		b.WriteString(" [MALFORMED]")
		return b.String()
	}
	fmt.Fprintf(&b, " - %d block(s), REPORTED not verified", len(r.Blocks))
	return b.String()
}
