package analyze

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	iscc "github.com/iscc/iscc-lib/packages/go"
	"github.com/richardwooding/c2pa"
	"github.com/richardwooding/fingerprint"
)

// publishedAudioCode is the ISCC Audio-Code iscc-sdk publishes for
// testdata/sample.mp3, in its tests/test_audio.py. It is the strongest
// assertion in this package: not "the code we computed last time" but the
// code the reference implementation of the standard computes for this exact
// file.
const publishedAudioCode = "ISCC:EIAWUJFCEZZOJYVD"

// isccAudioOf computes an Audio-Code the way isccOf computes an Image-Code:
// independently of the signing path, so a test asserts the wiring rather than
// restating it.
func isccAudioOf(t *testing.T, container c2pa.Container, asset []byte) (code string, digest []byte) {
	t.Helper()
	var (
		cv  []int32
		err error
	)
	if container == c2pa.MP3 {
		cv, err = fingerprint.ChromaprintFromMP3(bytes.NewReader(asset))
	} else {
		cv, err = fingerprint.ChromaprintFromWAV(bytes.NewReader(asset))
	}
	if err != nil {
		t.Fatalf("Chromaprint: %v", err)
	}
	c, err := iscc.GenAudioCodeV0(cv, isccBits)
	if err != nil {
		t.Fatalf("GenAudioCodeV0: %v", err)
	}
	d, err := iscc.IsccDecode(c.Iscc)
	if err != nil {
		t.Fatalf("IsccDecode: %v", err)
	}
	return c.Iscc, d.Digest
}

// TestSignSoftBindingMP3 is the audio feature end to end, against a published
// number rather than against itself.
//
// The recompute at the end is the assertion that matters, and it is not
// obvious it should hold: c2pa embeds an MP3 manifest in an ID3v2 GEOB frame,
// rewriting the tag section the file arrived with. The audio frames have to
// come through that untouched, and the Xing header the gapless trimming reads
// has to still be findable behind the new tag.
func TestSignSoftBindingMP3(t *testing.T) {
	asset, err := os.ReadFile("../../testdata/sample.mp3")
	if err != nil {
		t.Fatal(err)
	}
	wantCode, wantDigest := isccAudioOf(t, c2pa.MP3, asset)
	if wantCode != publishedAudioCode {
		t.Fatalf("this build computes %s for the fixture; iscc-sdk publishes %s", wantCode, publishedAudioCode)
	}

	signer, _ := testSigner(t, nil)
	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.MP3, bytes.NewReader(asset), &out,
		SignRequest{Title: "belly button", SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.SoftBinding != wantCode {
		t.Errorf("SoftBinding = %q, want %q", res.SoftBinding, wantCode)
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
		"registered":     "true",
		"from claim":     "false",
		"well formed":    "true",
		"name":           wantCode,
		"url":            "",
	})
	assertISCCBlock(t, sb, wantDigest)

	recomputed, _ := isccAudioOf(t, c2pa.MP3, out.Bytes())
	if recomputed != wantCode {
		t.Errorf("recomputing over the SIGNED MP3 gives %s, the assertion says %s", recomputed, wantCode)
	}
}

// TestSignSoftBindingWAV drives the other audio carrier. A WAV is a c2pa.RIFF
// exactly as a WebP is, so this and TestSignSoftBindingWebP are the two halves
// of the same fork: the container says nothing, the form type says everything.
func TestSignSoftBindingWAV(t *testing.T) {
	asset := synthWAV(44100, 2, 6)
	wantCode, wantDigest := isccAudioOf(t, c2pa.RIFF, asset)

	signer, _ := testSigner(t, nil)
	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.RIFF, bytes.NewReader(asset), &out,
		SignRequest{Title: "wav", SoftBinding: SoftBindingISCC})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.SoftBinding != wantCode || !strings.HasPrefix(res.SoftBinding, "ISCC:") {
		t.Errorf("SoftBinding = %q, want the ISCC %q", res.SoftBinding, wantCode)
	}
	if !res.Verify.Valid || res.Verify.Binding != "verified" {
		t.Fatalf("output valid = %v, binding = %q", res.Verify.Valid, res.Verify.Binding)
	}
	if len(res.Verify.SoftBindings) != 1 {
		t.Fatalf("read back %d soft bindings, want 1", len(res.Verify.SoftBindings))
	}
	assertISCCBlock(t, res.Verify.SoftBindings[0], wantDigest)

	// The RIFF embedder adds a chunk; the audio it describes must not move.
	if recomputed, _ := isccAudioOf(t, c2pa.RIFF, out.Bytes()); recomputed != wantCode {
		t.Errorf("recomputing over the SIGNED WAV gives %s, the assertion says %s", recomputed, wantCode)
	}
}

// TestAudioSoftBindingSurvivesResampling is the audio counterpart of
// TestSoftBindingSurvivesReencoding, and the reason a soft binding is worth
// writing at all: the same recording at a quarter of the sample rate, folded
// to mono and requantised, is a completely different set of bytes with a
// completely different hard binding, and the same identifier.
func TestAudioSoftBindingSurvivesResampling(t *testing.T) {
	base := synthWAV(44100, 2, 6)
	_, want := isccAudioOf(t, c2pa.RIFF, base)

	variants := map[string][]byte{
		"11025 mono":   synthWAV(11025, 1, 6),
		"22050 stereo": synthWAV(22050, 2, 6),
		"48000 mono":   synthWAV(48000, 1, 6),
	}
	for name, asset := range variants {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(asset, base) {
				t.Fatal("the variant is byte-identical to the base; this proves nothing")
			}
			code, digest := isccAudioOf(t, c2pa.RIFF, asset)
			d := hamming(want, digest)
			t.Logf("%s → %s, %d of %d bits differ", name, code, d, isccBits)
			if d > 4 {
				t.Errorf("%d of %d bits differ; resampling should barely move an ISCC", d, isccBits)
			}
		})
	}
}

// TestISCCMediaForRoutesOnContent pins the fork this feature turns on. A
// c2pa.Container names a carrier, and RIFF is the case that proves it: the
// same constant is an image or audio depending on four bytes at offset 8.
func TestISCCMediaForRoutesOnContent(t *testing.T) {
	cases := []struct {
		name      string
		container c2pa.Container
		data      []byte
		want      isccMedia
	}{
		{"jpeg", c2pa.JPEG, nil, isccMediaImage},
		{"png", c2pa.PNG, nil, isccMediaImage},
		{"gif", c2pa.GIF, nil, isccMediaImage},
		{"tiff", c2pa.TIFF, nil, isccMediaImage},
		{"mp3", c2pa.MP3, nil, isccMediaAudio},
		{"riff webp", c2pa.RIFF, riffOf("WEBP"), isccMediaImage},
		{"riff wave", c2pa.RIFF, riffOf("WAVE"), isccMediaAudio},
		{"riff avi", c2pa.RIFF, riffOf("AVI "), isccMediaNone},
		{"riff too short", c2pa.RIFF, []byte("RIFF"), isccMediaNone},
		{"bmff", c2pa.BMFF, nil, isccMediaNone},
		{"pdf", c2pa.PDF, nil, isccMediaNone},
		{"svg", c2pa.SVG, nil, isccMediaNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isccMediaFor(tc.container, tc.data); got != tc.want {
				t.Errorf("isccMediaFor = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestAudioGateAdmitsThenTheDecoderRefuses separates the two refusals that now
// look alike from outside. A WAV and an MP3 pass the format gate — they are
// audio this build knows how to route — and fail afterwards, on the content,
// with the decoder's own reason. Flattening those into ErrSoftBindingFormat
// would tell a user with a truncated WAV that WAVs are unsupported.
func TestAudioGateAdmitsThenTheDecoderRefuses(t *testing.T) {
	cases := map[string]struct {
		container c2pa.Container
		data      []byte
		want      string
	}{
		"riff wave that is not a wav":  {c2pa.RIFF, riffOf("WAVE"), "cannot read this WAV"},
		"mp3 that is not an mp3":       {c2pa.MP3, []byte("ID3\x04\x00\x00\x00\x00\x00\x00nope"), "cannot read this MP3"},
		"wav too short to fingerprint": {c2pa.RIFF, synthWAV(44100, 1, 1), "too short"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sb, code, err := softBindingFor(SoftBindingISCC, tc.container, tc.data)
			if err == nil {
				t.Fatalf("got %v / %q, want a refusal", sb, code)
			}
			if errors.Is(err, ErrSoftBindingFormat) {
				t.Errorf("refused as an unsupported FORMAT; the format is fine, the content is not: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if sb != nil || code != "" {
				t.Errorf("refusal still returned %v / %q", sb, code)
			}
		})
	}
}

// synthWAV builds deterministic test audio as a 16-bit PCM WAV.
//
// Integer arithmetic only, deliberately: Go permits fused multiply-add, so a
// floating-point generator is not guaranteed to produce identical bytes on
// every architecture, and the resampling test above compares fingerprints of
// audio generated at different rates. Three triangle partials plus a seeded
// noise floor keep every chroma bin occupied, which a pure tone would not.
func synthWAV(rate, channels, seconds int) []byte {
	n := rate * seconds
	samples := make([]int16, n*channels)

	periods := [3]int{max(rate/220, 2), max(rate/330, 2), max(rate/550, 2)}
	amps := [3]int32{9000, 4200, 2000}
	noise := uint32(0x9e3779b9)

	for i := range n {
		var v int32
		for j, p := range periods {
			phase := int32((i + j*7) % p)
			t := phase * 4 * amps[j] / int32(p)
			if t > 2*amps[j] {
				t = 4*amps[j] - t
			}
			v += t - amps[j]
		}
		noise = noise*1664525 + 1013904223
		v += int32(noise>>25) - 64

		for c := range channels {
			s := v
			if c == 1 {
				s = v/2 + int32((i*3)%1024) - 512
			}
			samples[i*channels+c] = int16(min(max(s, -32768), 32767))
		}
	}

	data := make([]byte, len(samples)*2)
	for i, s := range samples {
		binary.LittleEndian.PutUint16(data[2*i:], uint16(s))
	}
	blockAlign := channels * 2
	out := make([]byte, 0, 44+len(data))
	u32 := func(v uint32) { out = binary.LittleEndian.AppendUint32(out, v) }
	u16 := func(v uint16) { out = binary.LittleEndian.AppendUint16(out, v) }
	out = append(out, "RIFF"...)
	u32(uint32(36 + len(data)))
	out = append(out, "WAVEfmt "...)
	u32(16)
	u16(1)
	u16(uint16(channels))
	u32(uint32(rate))
	u32(uint32(rate * blockAlign))
	u16(uint16(blockAlign))
	u16(16)
	out = append(out, "data"...)
	u32(uint32(len(data)))
	return append(out, data...)
}
