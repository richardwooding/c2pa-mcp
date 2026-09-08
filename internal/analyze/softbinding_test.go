package analyze

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"strings"
	"testing"

	iscc "github.com/iscc/iscc-lib/packages/go"
	"github.com/richardwooding/c2pa"
	"github.com/richardwooding/fingerprint"
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

// TestSignSoftBindingISCC is the end-to-end feature: sign with --soft-binding
// iscc and the signed asset carries an io.iscc.v0 assertion holding the code's
// raw digest, which a verifier reads back and reports.
func TestSignSoftBindingISCC(t *testing.T) {
	assets := map[c2pa.Container][]byte{
		c2pa.PNG:  encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) }),
		c2pa.JPEG: encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, nil) }),
		c2pa.GIF:  encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return gif.Encode(w, img, nil) }),
	}
	signer, _ := testSigner(t, nil)
	for container, asset := range assets {
		t.Run(string(container), func(t *testing.T) {
			wantCode, wantDigest := isccOf(t, asset)

			var out bytes.Buffer
			res, err := signer.Sign(context.Background(), container, bytes.NewReader(asset), &out,
				SignRequest{Title: "scene", SoftBinding: SoftBindingISCC})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if res.SoftBinding != wantCode {
				t.Errorf("SoftBinding = %q, want %q", res.SoftBinding, wantCode)
			}
			if !strings.HasPrefix(res.SoftBinding, "ISCC:") {
				t.Errorf("SoftBinding = %q, want an ISCC: string", res.SoftBinding)
			}
			// §9.1: a soft binding never replaces the hard one.
			if !res.Verify.Valid || res.Verify.Binding != "verified" {
				t.Fatalf("output valid = %v, binding = %q; want a verified hard binding too", res.Verify.Valid, res.Verify.Binding)
			}

			if len(res.Verify.SoftBindings) != 1 {
				t.Fatalf("read back %d soft bindings, want 1", len(res.Verify.SoftBindings))
			}
			sb := res.Verify.SoftBindings[0]
			switch {
			case sb.Algorithm != isccAlgorithm:
				t.Errorf("algorithm = %q, want %q", sb.Algorithm, isccAlgorithm)
			case !sb.AlgorithmRegistered:
				t.Error("io.iscc.v0 should be on the embedded C2PA list")
			case sb.AlgorithmType != "fingerprint":
				t.Errorf("algorithm type = %q, want fingerprint", sb.AlgorithmType)
			case sb.AlgorithmFromClaim:
				t.Error("the algorithm is written per assertion, not as the claim's alg_soft")
			case !sb.WellFormed:
				t.Error("the assertion we wrote should read back well-formed")
			case sb.Name != wantCode:
				t.Errorf("name = %q, want the canonical %q", sb.Name, wantCode)
			case sb.Label != "c2pa.soft-binding":
				t.Errorf("label = %q, want c2pa.soft-binding", sb.Label)
			case sb.URL != "":
				t.Errorf("url = %q, want none written", sb.URL)
			}
			if len(sb.Blocks) != 1 {
				t.Fatalf("%d blocks, want 1", len(sb.Blocks))
			}
			got, err := base64.StdEncoding.DecodeString(sb.Blocks[0].Value)
			if err != nil {
				t.Fatalf("block value is not base64: %v", err)
			}
			if !bytes.Equal(got, wantDigest) {
				t.Errorf("block value = %x, want the ISCC digest %x", got, wantDigest)
			}
			if n := len(got); n != isccBits/8 {
				t.Errorf("digest is %d bytes, want %d for a %d-bit code", n, isccBits/8, isccBits)
			}
		})
	}
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
		"jpeg default": encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, nil) }),
		"jpeg q40":     encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, &jpeg.Options{Quality: 40}) }),
		"gif palette":  encodeScene(t, func(w *bytes.Buffer, img image.Image) error { return gif.Encode(w, img, nil) }),
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
		{"mp4", SoftBindingISCC, c2pa.BMFF, nil, ErrSoftBindingFormat},
		{"webp", SoftBindingISCC, c2pa.RIFF, nil, ErrSoftBindingFormat},
		{"tiff", SoftBindingISCC, c2pa.TIFF, nil, ErrSoftBindingFormat},
		{"svg", SoftBindingISCC, c2pa.SVG, nil, ErrSoftBindingFormat},
		{"mp3", SoftBindingISCC, c2pa.MP3, nil, ErrSoftBindingFormat},
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
	switch {
	case !r.AlgorithmFromClaim:
		t.Error("algorithm_from_claim lost")
	case r.AlgorithmRegistered:
		t.Error("phash is not on the C2PA list")
	case r.URL != "http://example.invalid/resolve":
		t.Errorf("url = %q; it must be reported (and never fetched)", r.URL)
	case len(r.Blocks) != 2:
		t.Fatalf("%d blocks, want 2", len(r.Blocks))
	}
	if r.Blocks[0].Value != base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) {
		t.Errorf("value = %q, want base64 of 010203", r.Blocks[0].Value)
	}
	if r.Blocks[0].TimespanStartMS == nil || *r.Blocks[0].TimespanStartMS != 1000 ||
		r.Blocks[0].TimespanEndMS == nil || *r.Blocks[0].TimespanEndMS != 2000 {
		t.Errorf("timespan = %v..%v, want 1000..2000", r.Blocks[0].TimespanStartMS, r.Blocks[0].TimespanEndMS)
	}
	if r.Blocks[1].TimespanStartMS != nil {
		t.Error("a block with no timespan should omit it")
	}
	if !r.Blocks[1].HasRegion || !r.Blocks[1].HasExtent {
		t.Errorf("region/extent scope not reported: %+v", r.Blocks[1])
	}
	if line := r.summarize(); !strings.Contains(line, "not on this build's copy") || !strings.Contains(line, "2 block(s)") {
		t.Errorf("summary line = %q", line)
	}
	if line := reports[1].summarize(); !strings.Contains(line, "MALFORMED") {
		t.Errorf("a malformed soft binding must say so: %q", line)
	}
}
