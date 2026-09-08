package analyze

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	iscc "github.com/iscc/iscc-lib/packages/go"
	"github.com/richardwooding/c2pa"
	"github.com/richardwooding/fingerprint"
	"golang.org/x/image/tiff"
)

// isccScene is a 96x96 image with enough structure for an Image-Code to be
// about the content rather than about the encoder: the 16x16 gradient the other
// signing tests use normalises to something a re-encode can move.
func isccScene() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 96, 96))
	for y := range 96 {
		for x := range 96 {
			v := math.Sin(float64(x)/9)*math.Cos(float64(y)/7)*120 + 128
			img.Set(x, y, color.RGBA{uint8(v), uint8(int(v)/2 + 40), uint8(255 - int(v)), 255})
		}
	}
	return img
}

func encodeScene(t *testing.T, encode func(*bytes.Buffer, image.Image) error) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := encode(&buf, isccScene()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// isccSceneAssets encodes the scene into every container this build can both
// sign and fingerprint, keyed by the container the signer needs.
func isccSceneAssets(t *testing.T) map[c2pa.Container][]byte {
	t.Helper()
	return map[c2pa.Container][]byte{
		c2pa.PNG:  encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) }),
		c2pa.JPEG: encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, nil) }),
		c2pa.GIF:  encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return gif.Encode(w, img, nil) }),
		// x/image/tiff writes uncompressed little-endian RGB, which is enough
		// to sign; WebP has no Go encoder, so it needs the fixture below.
		c2pa.TIFF: encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return tiff.Encode(w, img, nil) }),
	}
}

// isccOf computes the code the recipe produces, independently of the signing
// path, so a test can assert the wiring rather than restate it.
func isccOf(t *testing.T, asset []byte) (code string, digest []byte) {
	t.Helper()
	pixels, err := fingerprint.ISCCPixelsFromReader(bytes.NewReader(asset))
	if err != nil {
		t.Fatalf("ISCCPixelsFromReader: %v", err)
	}
	c, err := iscc.GenImageCodeV0(pixels, isccBits)
	if err != nil {
		t.Fatalf("GenImageCodeV0: %v", err)
	}
	d, err := iscc.IsccDecode(c.Iscc)
	if err != nil {
		t.Fatalf("IsccDecode: %v", err)
	}
	return c.Iscc, d.Digest
}

func hamming(a, b []byte) int {
	if len(a) != len(b) {
		return 8 * max(len(a), len(b))
	}
	n := 0
	for i := range a {
		n += bits.OnesCount8(a[i] ^ b[i])
	}
	return n
}

// softBindingFields flattens the scalar fields worth asserting into comparable
// strings. A map plus one loop replaces a chain of branches, which the review
// gate counts against us — and it reports EVERY wrong field, where a switch
// stopped at the first.
func softBindingFields(sb SoftBindingReport) map[string]string {
	return map[string]string{
		"label":          sb.Label,
		"algorithm":      sb.Algorithm,
		"algorithm type": sb.AlgorithmType,
		"registered":     strconv.FormatBool(sb.AlgorithmRegistered),
		"from claim":     strconv.FormatBool(sb.AlgorithmFromClaim),
		"well formed":    strconv.FormatBool(sb.WellFormed),
		"name":           sb.Name,
		"url":            sb.URL,
	}
}

// assertFields names every field of a flattened report that differs from what
// was expected. Fields absent from want are not asserted.
func assertFields(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for field, w := range want {
		if g := got[field]; g != w {
			t.Errorf("%s = %q, want %q", field, g, w)
		}
	}
}

// assertISCCBlock checks the one block an ISCC soft binding carries: the code's
// raw digest, base64 as the report presents it.
func assertISCCBlock(t *testing.T, sb SoftBindingReport, wantDigest []byte) {
	t.Helper()
	if len(sb.Blocks) != 1 {
		t.Fatalf("%d blocks, want 1", len(sb.Blocks))
	}
	got, err := base64.StdEncoding.DecodeString(sb.Blocks[0].Value)
	if err != nil {
		t.Fatalf("block value is not base64: %v", err)
	}
	if !bytes.Equal(got, wantDigest) {
		t.Fatalf("block value = %x, want the ISCC digest %x", got, wantDigest)
	}
	if n := len(got); n != isccBits/8 {
		t.Errorf("digest is %d bytes, want %d for a %d-bit code", n, isccBits/8, isccBits)
	}
}

// TestSignSoftBindingISCC is the end-to-end feature: sign with --soft-binding
// iscc and the signed asset carries an io.iscc.v0 assertion holding the code's
// raw digest, which a verifier reads back and reports.
func TestSignSoftBindingISCC(t *testing.T) {
	assets := isccSceneAssets(t)
	signer, _ := testSigner(t, nil)
	for container, asset := range assets {
		t.Run(string(container), func(t *testing.T) {
			assertSignsWithISCC(t, signer, container, asset)
		})
	}
}

// assertSignsWithISCC signs one asset with a soft binding and checks everything
// a verifier should then read back out of it.
func assertSignsWithISCC(t *testing.T, signer *Signer, container c2pa.Container, asset []byte) {
	t.Helper()
	wantCode, wantDigest := isccOf(t, asset)

	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), container, bytes.NewReader(asset), &out,
		SignRequest{Title: "scene", SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.SoftBinding != wantCode || !strings.HasPrefix(res.SoftBinding, "ISCC:") {
		t.Errorf("SoftBinding = %q, want the ISCC %q", res.SoftBinding, wantCode)
	}
	// §9.1: a soft binding never replaces the hard one.
	if !res.Verify.Valid || res.Verify.Binding != "verified" {
		t.Fatalf("output valid = %v, binding = %q; want a verified hard binding too", res.Verify.Valid, res.Verify.Binding)
	}
	if len(res.Verify.SoftBindings) != 1 {
		t.Fatalf("read back %d soft bindings, want 1", len(res.Verify.SoftBindings))
	}

	sb := res.Verify.SoftBindings[0]
	assertFields(t, softBindingFields(sb), map[string]string{
		"label":          "c2pa.soft-binding",
		"algorithm":      isccAlgorithm,
		"algorithm type": "fingerprint",
		"registered":     "true",  // io.iscc.v0 is on the embedded C2PA list
		"from claim":     "false", // written per assertion, not as the claim's alg_soft
		"well formed":    "true",
		"name":           wantCode, // the canonical string, for humans
		"url":            "",       // deprecated; this writer emits none
	})
	assertISCCBlock(t, sb, wantDigest)
}

// TestSoftBindingRecomputableFromSignedAsset is the property the whole feature
// exists for: whoever holds the signed file can recompute the code and get the
// one in the assertion back. Embedding a manifest must not move it.
func TestSoftBindingRecomputableFromSignedAsset(t *testing.T) {
	asset := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })
	signer, _ := testSigner(t, nil)

	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(asset), &out, SignRequest{SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	recomputed, _ := isccOf(t, out.Bytes())
	if recomputed != res.SoftBinding {
		t.Errorf("recomputing over the SIGNED asset gives %s, the assertion says %s", recomputed, res.SoftBinding)
	}
}

// TestSoftBindingSurvivesReencoding is the difference from a hard binding: the
// bytes change, the identifier does not. The bound has headroom for decoder
// drift; the codes were identical when this was written, which the log shows.
func TestSoftBindingSurvivesReencoding(t *testing.T) {
	base := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })
	_, want := isccOf(t, base)

	reencodings := map[string][]byte{
		"jpeg default":  encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, nil) }),
		"jpeg q40":      encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, &jpeg.Options{Quality: 40}) }),
		"gif palette":   encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return gif.Encode(w, img, nil) }),
		"tiff lossless": encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return tiff.Encode(w, img, nil) }),
		"tiff deflate": encodeScene(t, func(w *bytes.Buffer, img image.Image) error {
			return tiff.Encode(w, img, &tiff.Options{Compression: tiff.Deflate})
		}),
	}
	for name, asset := range reencodings {
		t.Run(name, func(t *testing.T) {
			code, digest := isccOf(t, asset)
			d := hamming(want, digest)
			t.Logf("%s → %s, %d of %d bits differ", name, code, d, isccBits)
			if d > 4 {
				t.Errorf("%d of %d bits differ; a re-encode should barely move an ISCC", d, isccBits)
			}
		})
	}
}

func TestSignSoftBindingDefaultsToNone(t *testing.T) {
	asset := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })
	signer, _ := testSigner(t, nil)

	for _, alg := range []string{"", SoftBindingNone} {
		var out bytes.Buffer
		res, err := signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(asset), &out, SignRequest{SoftBinding: alg})
		if err != nil {
			t.Fatalf("Sign(%q): %v", alg, err)
		}
		if res.SoftBinding != "" || len(res.Verify.SoftBindings) != 0 {
			t.Errorf("Sign(%q) wrote soft binding %q / %d assertions, want none", alg, res.SoftBinding, len(res.Verify.SoftBindings))
		}
	}
}

// TestSoftBindingForRefusals pins the gate rather than the computation: an
// algorithm this build cannot compute, and a container it cannot decode. Both
// refuse — a code computed from the wrong pixels would be silently wrong.
func TestSoftBindingForRefusals(t *testing.T) {
	pngAsset := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })

	cases := []struct {
		name      string
		alg       string
		container c2pa.Container
		data      []byte
		want      error
	}{
		{"unknown algorithm", "phash", c2pa.PNG, pngAsset, ErrSoftBindingAlgorithm},
		{"a watermark we cannot compute", "com.digimarc.v1", c2pa.PNG, pngAsset, ErrSoftBindingAlgorithm},
		{"pdf", SoftBindingISCC, c2pa.PDF, nil, ErrSoftBindingFormat},
		{"mp4 or heic — same container to c2pa", SoftBindingISCC, c2pa.BMFF, nil, ErrSoftBindingFormat},
		{"svg", SoftBindingISCC, c2pa.SVG, nil, ErrSoftBindingFormat},
		{"mp3", SoftBindingISCC, c2pa.MP3, nil, ErrSoftBindingFormat},
		// A WAV is a c2pa.RIFF exactly as a WebP is, which is why the gate has
		// to read the form type rather than trust the container.
		{"wav, not webp", SoftBindingISCC, c2pa.RIFF, riffOf("WAVE"), ErrSoftBindingFormat},
		{"avi, not webp", SoftBindingISCC, c2pa.RIFF, riffOf("AVI "), ErrSoftBindingFormat},
		{"riff too short to name a form", SoftBindingISCC, c2pa.RIFF, []byte("RIFF"), ErrSoftBindingFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb, code, err := softBindingFor(tc.alg, tc.container, tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if sb != nil || code != "" {
				t.Errorf("refusal still returned %v / %q", sb, code)
			}
		})
	}

	// The registry identifier works in place of the short name.
	sb, code, err := softBindingFor(isccAlgorithm, c2pa.PNG, pngAsset)
	if err != nil || sb == nil || !strings.HasPrefix(code, "ISCC:") {
		t.Fatalf("softBindingFor(%q) = %v, %q, %v", isccAlgorithm, sb, code, err)
	}

	// Something that is a JPEG to the C2PA reader but not to an image decoder.
	if _, _, err := softBindingFor(SoftBindingISCC, c2pa.JPEG, []byte("\xff\xd8\xff not really")); err == nil {
		t.Error("an undecodable image should be an error, not a code computed from nothing")
	}
}

// TestSignSoftBindingRefusalWritesNothing checks the refusal happens before any
// output exists: a soft binding this build cannot compute must not leave a
// signed file that silently lacks one.
func TestSignSoftBindingRefusalWritesNothing(t *testing.T) {
	asset := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })
	signer, _ := testSigner(t, nil)
	out := filepath.Join(t.TempDir(), "signed.png")

	_, err := signer.SignToFile(context.Background(), c2pa.PNG, bytes.NewReader(asset), out, false,
		SignRequest{SoftBinding: "nonesuch"})
	if !errors.Is(err, ErrSoftBindingAlgorithm) {
		t.Fatalf("error = %v, want ErrSoftBindingAlgorithm", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused sign left %s behind (%v)", out, err)
	}
}

// TestVerifyReportsSoftBinding goes through the real verify entry point — the
// embedded trust list, no anchor for our throwaway chain — because that is what
// a user runs. The verdict is invalid on trust, and the soft binding is still
// reported: it is independent of the signature's fate.
func TestVerifyReportsSoftBinding(t *testing.T) {
	asset := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })
	signer, _ := testSigner(t, nil)

	var signed bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(asset), &signed, SignRequest{SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := Verify(context.Background(), c2pa.PNG, bytes.NewReader(signed.Bytes()), VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.SoftBindings) != 1 || got.SoftBindings[0].Name != res.SoftBinding {
		t.Fatalf("verify reported %+v, want the ISCC %q", got.SoftBindings, res.SoftBinding)
	}
	summary := got.Summary()
	if !strings.Contains(summary, "Soft binding") || !strings.Contains(summary, "REPORTED not verified") {
		t.Errorf("summary must say a soft binding was not checked; got:\n%s", summary)
	}
	if !strings.Contains(summary, res.SoftBinding) {
		t.Errorf("summary should name the code %q; got:\n%s", res.SoftBinding, summary)
	}
}

// TestSoftBindingReportShapesEveryField covers what no manifest this tool
// writes carries: another producer's deprecated url and extent, a timespan, a
// region, an unregistered algorithm named by the claim, and a malformed one.
func TestSoftBindingReportShapesEveryField(t *testing.T) {
	reports := toSoftBindingReports([]c2pa.SoftBinding{{
		Label:              "c2pa.soft-binding",
		Algorithm:          "phash",
		AlgorithmFromClaim: true,
		Name:               "a watermark, allegedly",
		URL:                "http://example.invalid/resolve",
		WellFormed:         true,
		Blocks: []c2pa.SoftBindingBlock{
			{Value: []byte{1, 2, 3}, Scope: c2pa.SoftBindingScope{Timespan: &c2pa.SoftBindingTimespan{Start: 1000, End: 2000}}},
			{Value: []byte{4}, Scope: c2pa.SoftBindingScope{Region: []byte{0xA0}, Extent: []byte{0x01}}},
		},
	}, {
		Label:      "c2pa.soft-binding__1",
		Algorithm:  "io.iscc.v0",
		WellFormed: false,
	}})

	if len(reports) != 2 {
		t.Fatalf("%d reports, want 2", len(reports))
	}
	r := reports[0]
	assertFields(t, softBindingFields(r), map[string]string{
		"label":          "c2pa.soft-binding",
		"algorithm":      "phash",
		"algorithm type": "",      // not on the list, so we have no type for it
		"registered":     "false", // the spec's own example algorithm is unregistered
		"from claim":     "true",
		"well formed":    "true",
		"name":           "a watermark, allegedly",
		// Reported so nothing is hidden, and never fetched.
		"url": "http://example.invalid/resolve",
	})
	if len(r.Blocks) != 2 {
		t.Fatalf("%d blocks, want 2", len(r.Blocks))
	}
	assertScopedBlock(t, r.Blocks[0], []byte{1, 2, 3}, 1000, 2000)
	assertUnscopedBlock(t, r.Blocks[1], []byte{4})

	if line := r.summarize(); !strings.Contains(line, "not on this build's copy") || !strings.Contains(line, "2 block(s)") {
		t.Errorf("summary line = %q", line)
	}
	if line := reports[1].summarize(); !strings.Contains(line, "MALFORMED") {
		t.Errorf("a malformed soft binding must say so: %q", line)
	}
}

// assertScopedBlock checks a block carrying a timespan.
func assertScopedBlock(t *testing.T, b SoftBindingBlockReport, wantValue []byte, start, end uint64) {
	t.Helper()
	if b.Value != base64.StdEncoding.EncodeToString(wantValue) {
		t.Errorf("value = %q, want base64 of %x", b.Value, wantValue)
	}
	if b.TimespanStartMS == nil || b.TimespanEndMS == nil {
		t.Fatalf("timespan lost: %+v", b)
	}
	if *b.TimespanStartMS != start || *b.TimespanEndMS != end {
		t.Errorf("timespan = %d..%d, want %d..%d", *b.TimespanStartMS, *b.TimespanEndMS, start, end)
	}
}

// assertUnscopedBlock checks a block with a region and the deprecated extent,
// both of which are reported as present without being decoded.
func assertUnscopedBlock(t *testing.T, b SoftBindingBlockReport, wantValue []byte) {
	t.Helper()
	if b.Value != base64.StdEncoding.EncodeToString(wantValue) {
		t.Errorf("value = %q, want base64 of %x", b.Value, wantValue)
	}
	if b.TimespanStartMS != nil {
		t.Error("a block with no timespan should omit it")
	}
	if !b.HasRegion || !b.HasExtent {
		t.Errorf("region/extent scope not reported: %+v", b)
	}
}

// riffOf builds the smallest RIFF file that names a form type, which is all the
// gate reads.
func riffOf(form string) []byte {
	return append([]byte("RIFF\x00\x00\x00\x00"), form...)
}

// TestSignSoftBindingWebP is the format that needed a real file: Go can decode
// a WebP but not write one, so this drives a genuine libwebp-encoded asset all
// the way through.
//
// The assertion that matters is the recompute: c2pa's RIFF embedder SYNTHESISES
// a VP8X chunk for a simple-format WebP, restructuring the container around the
// bitstream. If that moved a single pixel — or if x/image could not read the
// result back — the code recovered from the signed file would differ from the
// one in its own assertion, and a resolver would never match it.
func TestSignSoftBindingWebP(t *testing.T) {
	asset, err := os.ReadFile("../../testdata/sample.webp")
	if err != nil {
		t.Fatal(err)
	}
	if !isWebP(asset) {
		t.Fatal("fixture is not a WebP")
	}
	wantCode, wantDigest := isccOf(t, asset)

	signer, _ := testSigner(t, nil)
	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.RIFF, bytes.NewReader(asset), &out,
		SignRequest{Title: "webp", SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.SoftBinding != wantCode {
		t.Errorf("SoftBinding = %q, want %q", res.SoftBinding, wantCode)
	}
	if !res.Verify.Valid || res.Verify.Binding != "verified" {
		t.Fatalf("output valid = %v, binding = %q", res.Verify.Valid, res.Verify.Binding)
	}
	if len(res.Verify.SoftBindings) != 1 {
		t.Fatalf("read back %d soft bindings, want 1", len(res.Verify.SoftBindings))
	}
	assertISCCBlock(t, res.Verify.SoftBindings[0], wantDigest)

	// Embedding a manifest must not move the content it describes.
	recomputed, _ := isccOf(t, out.Bytes())
	if recomputed != wantCode {
		t.Errorf("recomputing over the SIGNED WebP gives %s, the assertion says %s", recomputed, wantCode)
	}
}

// TestSignSoftBindingTIFF signs the container whose refusals live one module
// away, and checks the code survives the new last IFD c2pa links in.
func TestSignSoftBindingTIFF(t *testing.T) {
	asset := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return tiff.Encode(w, img, nil) })
	wantCode, _ := isccOf(t, asset)

	signer, _ := testSigner(t, nil)
	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.TIFF, bytes.NewReader(asset), &out,
		SignRequest{SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.SoftBinding != wantCode {
		t.Errorf("SoftBinding = %q, want %q", res.SoftBinding, wantCode)
	}
	if recomputed, _ := isccOf(t, out.Bytes()); recomputed != wantCode {
		t.Errorf("recomputing over the SIGNED TIFF gives %s, want %s", recomputed, wantCode)
	}
}

// TestSoftBindingRefusesMisleadingTIFF: fingerprint refuses the TIFF layouts
// x/image misreads, and the reason has to reach the user rather than being
// flattened into "unsupported".
func TestSoftBindingRefusesMisleadingTIFF(t *testing.T) {
	// A DNG is a TIFF carrying DNGVersion (0xC612), and c2pa signs it happily.
	dng := encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return tiff.Encode(w, img, nil) })
	dng = withTIFFTag(t, dng, 0xC612, 1, 4, 0x00000401)

	_, _, err := softBindingFor(SoftBindingISCC, c2pa.TIFF, dng)
	if err == nil {
		t.Fatal("a DNG must not yield a code computed from its preview")
	}
	if !strings.Contains(err.Error(), "DNG") {
		t.Errorf("error should name the reason, got %q", err)
	}
}

// withTIFFTag splices one entry into a TIFF's first IFD, rewriting the entry
// count and shifting every value offset that follows. Only tags whose value
// fits inline are supported, which is all this test needs.
func withTIFFTag(t *testing.T, data []byte, tag, typ uint16, count, value uint32) []byte {
	t.Helper()
	if string(data[:2]) != "II" {
		t.Fatalf("expected a little-endian TIFF, got %q", data[:2])
	}
	bo := binary.LittleEndian
	ifd := int(bo.Uint32(data[4:]))
	n := int(bo.Uint16(data[ifd:]))

	entry := make([]byte, 0, 12)
	entry = bo.AppendUint16(entry, tag)
	entry = bo.AppendUint16(entry, typ)
	entry = bo.AppendUint32(entry, count)
	entry = bo.AppendUint32(entry, value)

	// Entries must stay sorted by tag; 0xC612 is high, so it goes last.
	insertAt := ifd + 2 + n*12
	out := make([]byte, 0, len(data)+12)
	out = append(out, data[:insertAt]...)
	out = append(out, entry...)
	out = append(out, data[insertAt:]...)
	bo.PutUint16(out[ifd:], uint16(n+1))

	// Every offset past the insertion point moves by the 12 bytes we added.
	for i := range n + 1 {
		e := ifd + 2 + i*12
		etag, etyp, ecount := bo.Uint16(out[e:]), bo.Uint16(out[e+2:]), bo.Uint32(out[e+4:])
		if etag == tag {
			continue
		}
		width := map[uint16]uint32{1: 1, 2: 1, 3: 2, 4: 4, 5: 8}[etyp]
		if width*ecount <= 4 {
			continue // the value is inline, not an offset
		}
		if v := bo.Uint32(out[e+8:]); int(v) >= insertAt {
			bo.PutUint32(out[e+8:], v+12)
		}
	}
	if v := bo.Uint32(out[4:]); int(v) >= insertAt {
		bo.PutUint32(out[4:], v+12)
	}
	return out
}
