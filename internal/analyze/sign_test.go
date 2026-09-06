package analyze

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-mcp/internal/testpki"
)

func testSigner(t *testing.T, tweak func(*SignerConfig)) (*Signer, testpki.Credentials) {
	t.Helper()
	creds, err := testpki.SelfSigned("Test Signer")
	if err != nil {
		t.Fatal(err)
	}
	cfg := SignerConfig{KeyPEM: creds.KeyPEM(), CertPEM: creds.CertPEM(), ClaimGenerator: "c2pa-mcp-test", ClaimGeneratorVersion: "0.0.1"}
	if tweak != nil {
		tweak(&cfg)
	}
	s, err := LoadSigner(cfg)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	return s, creds
}

func unsignedImage(t *testing.T, encode func(*bytes.Buffer, image.Image) error) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for x := range 16 {
		for y := range 16 {
			img.Set(x, y, color.RGBA{uint8(x * 16), uint8(y * 16), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func unsignedJPEG(t *testing.T) []byte {
	return unsignedImage(t, func(w *bytes.Buffer, img image.Image) error { return jpeg.Encode(w, img, nil) })
}

func unsignedPNG(t *testing.T) []byte {
	return unsignedImage(t, func(w *bytes.Buffer, img image.Image) error { return png.Encode(w, img) })
}

// assertNoPEMLeak fails when an error message carries PEM material.
func assertNoPEMLeak(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "AAAA")) {
		t.Fatalf("error echoes PEM material: %v", err)
	}
}

func TestLoadSigner_Accepts(t *testing.T) {
	creds, err := testpki.SelfSigned("Loader")
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]byte{}, creds.KeyPEM()...), creds.CertPEM()...)
	cases := map[string]SignerConfig{
		"pkcs8":                  {KeyPEM: creds.KeyPEM(), CertPEM: creds.CertPEM()},
		"sec1":                   {KeyPEM: creds.KeyPEMSEC1(), CertPEM: creds.CertPEM()},
		"combined file for both": {KeyPEM: combined, CertPEM: combined},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := LoadSigner(cfg)
			if err != nil {
				t.Fatalf("LoadSigner: %v", err)
			}
			if s.Name() != "Loader" || s.Timestamped() {
				t.Fatalf("Name = %q, Timestamped = %v", s.Name(), s.Timestamped())
			}
		})
	}
}

func TestLoadSigner_Rejects(t *testing.T) {
	creds, err := testpki.SelfSigned("Loader")
	if err != nil {
		t.Fatal(err)
	}
	other, err := testpki.SelfSigned("Someone Else")
	if err != nil {
		t.Fatal(err)
	}
	encrypted := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")
	badCert := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	cases := []struct {
		name    string
		cfg     SignerConfig
		wantErr error
	}{
		{"no key block", SignerConfig{KeyPEM: creds.CertPEM(), CertPEM: creds.CertPEM()}, ErrSigningKey},
		{"garbage key", SignerConfig{KeyPEM: []byte("not pem"), CertPEM: creds.CertPEM()}, ErrSigningKey},
		{"encrypted key", SignerConfig{KeyPEM: encrypted, CertPEM: creds.CertPEM()}, ErrSigningKey},
		{"no cert block", SignerConfig{KeyPEM: creds.KeyPEM(), CertPEM: creds.KeyPEM()}, ErrSigningCert},
		{"garbage cert", SignerConfig{KeyPEM: creds.KeyPEM(), CertPEM: badCert}, ErrSigningCert},
		{"key does not match cert", SignerConfig{KeyPEM: creds.KeyPEM(), CertPEM: other.CertPEM()}, c2pa.ErrSignerChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadSigner(tc.cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			assertNoPEMLeak(t, err)
		})
	}
	t.Run("encrypted key names the remedy", func(t *testing.T) {
		_, err := LoadSigner(SignerConfig{KeyPEM: encrypted, CertPEM: creds.CertPEM()})
		if err == nil || !strings.Contains(err.Error(), "encrypted") {
			t.Fatalf("err = %v, want a mention of encryption", err)
		}
	})
}

// assertCreated checks the shape of a fresh c2pa.created signing.
func assertCreated(t *testing.T, res SignResult, container c2pa.Container, inputLen, outLen int) {
	t.Helper()
	if res.Action != c2pa.ActionCreated || res.ChainedPriorManifest || res.Timestamped {
		t.Fatalf("result = %+v", res)
	}
	if res.Size != outLen || outLen <= inputLen {
		t.Fatalf("size %d, wrote %d, input %d", res.Size, outLen, inputLen)
	}
	if res.Container != string(container) || res.Output != "" || res.SignedBytes != "" {
		t.Fatalf("result = %+v", res)
	}
	if !res.Verify.Valid || res.Verify.VerifiedSigner != "Test Signer" || res.Verify.Detect.Title != "hello.img" {
		t.Fatalf("verify = %+v", res.Verify)
	}
	if !strings.Contains(res.Summary(), "SIGNED: c2pa.created") || !strings.Contains(res.Summary(), "VALID") {
		t.Fatalf("summary: %s", res.Summary())
	}
}

// assertReadsBack checks a signed asset through the ordinary verify and detect
// paths, with the signer's certificate as the anchor.
func assertReadsBack(t *testing.T, container c2pa.Container, out []byte, certPEM []byte) {
	t.Helper()
	ctx := context.Background()
	v, err := Verify(ctx, container, bytes.NewReader(out), VerifyOptions{SigningTrustPEM: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || !hasStatus(v, "assertion.dataHash.match") || !hasStatus(v, "signingCredential.trusted") {
		t.Fatalf("verify of output: %+v", v.Statuses)
	}
	d := Detect(ctx, container, bytes.NewReader(out))
	if !d.Present || !strings.Contains(d.ClaimGenerator, "c2pa-mcp-test") || d.SignedBy != "Test Signer" {
		t.Fatalf("detect of output: %+v", d)
	}
}

func TestSign_Created(t *testing.T) {
	s, creds := testSigner(t, nil)
	for _, tc := range []struct {
		name      string
		container c2pa.Container
		data      []byte
	}{{"jpeg", c2pa.JPEG, unsignedJPEG(t)}, {"png", c2pa.PNG, unsignedPNG(t)}} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			res, err := s.Sign(context.Background(), tc.container, bytes.NewReader(tc.data), &out, SignRequest{Title: "hello.img", DigitalSourceType: "digitalCapture"})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			assertCreated(t, res, tc.container, len(tc.data), out.Len())
			assertReadsBack(t, tc.container, out.Bytes(), creds.CertPEM())
		})
	}
}

func TestSign_AutoOpensSignedAsset(t *testing.T) {
	s, _ := testSigner(t, nil)
	ctx := context.Background()
	var out bytes.Buffer
	res, err := s.Sign(ctx, c2pa.JPEG, bytes.NewReader(readFixture(t)), &out, SignRequest{Title: "re-signed"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.Action != c2pa.ActionOpened || !res.ChainedPriorManifest {
		t.Fatalf("result = %+v", res)
	}
	if !res.Verify.Valid {
		t.Fatalf("output not valid at depth 0: %+v", res.Verify.Statuses)
	}
	if d := Detect(ctx, c2pa.JPEG, bytes.NewReader(out.Bytes())); d.Title != "re-signed" || d.SignedBy != "Test Signer" {
		t.Fatalf("detect: %+v", d)
	}
	// The prior manifest is still there and a full verify descends into it:
	// two claim signatures verify, ours and the fixture's. (The fixture's
	// signer and TSA are untrusted here, so it never reaches
	// ingredient.manifest.validated — that is the verify tool's honest verdict,
	// and exactly why Sign's own report stops at depth 0.)
	v, err := Verify(ctx, c2pa.JPEG, bytes.NewReader(out.Bytes()), VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]bool{}
	for _, st := range v.Statuses {
		if st.Code == "claimSignature.validated" {
			labels[st.URI] = true
		}
	}
	if len(labels) != 2 {
		t.Fatalf("want two validated claim signatures (ours and the prior manifest's), got %v", labels)
	}
}

func TestSign_Refusals(t *testing.T) {
	s, _ := testSigner(t, nil)
	ctx := context.Background()
	cases := []struct {
		name      string
		container c2pa.Container
		data      []byte
		req       SignRequest
		wantErr   error
	}{
		{"created on a signed asset", c2pa.JPEG, readFixture(t), SignRequest{Action: "created"}, c2pa.ErrManifestInvalid},
		{"bad action", c2pa.JPEG, unsignedJPEG(t), SignRequest{Action: "edited"}, ErrBadAction},
		{"not a jpeg", c2pa.JPEG, []byte("definitely not an image"), SignRequest{}, c2pa.ErrMalformedAsset},
		{"empty input", c2pa.PNG, nil, SignRequest{}, c2pa.ErrMalformedAsset},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := s.Sign(ctx, tc.container, bytes.NewReader(tc.data), &out, tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if out.Len() != 0 {
				t.Fatalf("%d bytes written on error", out.Len())
			}
		})
	}
}

func TestSign_TimestampFailureWritesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s, _ := testSigner(t, func(c *SignerConfig) {
		c.TimestampAuthority = srv.URL
		c.HTTPClient = srv.Client()
	})
	if !s.Timestamped() {
		t.Fatal("Timestamped = false with a TSA configured")
	}
	var out bytes.Buffer
	_, err := s.Sign(context.Background(), c2pa.JPEG, bytes.NewReader(unsignedJPEG(t)), &out, SignRequest{})
	if !errors.Is(err, c2pa.ErrTimestamp) {
		t.Fatalf("err = %v, want ErrTimestamp", err)
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes written on TSA failure", out.Len())
	}
}

// signedFile signs an unsigned JPEG into dir/signed.jpg and returns the path
// and the bytes written, asserting the temp file was cleaned up.
func signedFile(t *testing.T, s *Signer, dir string) (string, []byte) {
	t.Helper()
	out := filepath.Join(dir, "signed.jpg")
	res, err := s.SignToFile(context.Background(), c2pa.JPEG, bytes.NewReader(unsignedJPEG(t)), out, false, SignRequest{Title: "file"})
	if err != nil {
		t.Fatalf("SignToFile: %v", err)
	}
	if res.Output != out {
		t.Fatalf("Output = %q", res.Output)
	}
	data, err := os.ReadFile(out)
	if err != nil || len(data) != res.Size {
		t.Fatalf("read output: %v, %d bytes want %d", err, len(data), res.Size)
	}
	assertOnlyOutput(t, dir)
	return out, data
}

// assertOnlyOutput fails when anything but the signed file is left in dir.
func assertOnlyOutput(t *testing.T, dir string) {
	t.Helper()
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

// assertUnchanged fails when path no longer holds want.
func assertUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	if got, _ := os.ReadFile(path); !bytes.Equal(got, want) {
		t.Fatalf("%s changed", path)
	}
}

func TestSignToFile(t *testing.T) {
	s, _ := testSigner(t, nil)
	out, data := signedFile(t, s, t.TempDir())
	if d := Detect(context.Background(), c2pa.JPEG, bytes.NewReader(data)); d.Title != "file" {
		t.Fatalf("detect: %+v", d)
	}
	_ = out
}

func TestSignToFile_RefusesOverwrite(t *testing.T) {
	s, _ := testSigner(t, nil)
	out, data := signedFile(t, s, t.TempDir())
	_, err := s.SignToFile(context.Background(), c2pa.JPEG, bytes.NewReader(unsignedJPEG(t)), out, false, SignRequest{Title: "again"})
	if !errors.Is(err, ErrOutputExists) {
		t.Fatalf("err = %v, want ErrOutputExists", err)
	}
	assertUnchanged(t, out, data)
}

func TestSignToFile_FailureKeepsExisting(t *testing.T) {
	s, _ := testSigner(t, nil)
	dir := t.TempDir()
	out, data := signedFile(t, s, dir)
	if _, err := s.SignToFile(context.Background(), c2pa.JPEG, bytes.NewReader([]byte("junk")), out, true, SignRequest{}); err == nil {
		t.Fatal("expected an error signing junk")
	}
	assertUnchanged(t, out, data)
	assertOnlyOutput(t, dir)
}

func TestSignToFile_InPlace(t *testing.T) {
	s, _ := testSigner(t, nil)
	out, data := signedFile(t, s, t.TempDir())
	res, err := s.SignToFile(context.Background(), c2pa.JPEG, bytes.NewReader(data), out, true, SignRequest{Title: "in place"})
	if err != nil {
		t.Fatalf("overwrite in place: %v", err)
	}
	if res.Action != c2pa.ActionOpened || !res.ChainedPriorManifest {
		t.Fatalf("in-place re-sign should chain: %+v", res)
	}
	final, _ := os.ReadFile(out)
	if d := Detect(context.Background(), c2pa.JPEG, bytes.NewReader(final)); d.Title != "in place" {
		t.Fatalf("detect after in-place: %+v", d)
	}
}

func TestDigitalSourceTypeURL(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"empty":                                c2pa.DigitalSourceTypeEmpty,
		"digitalCapture":                       c2pa.DigitalSourceTypeDigitalCapture,
		"trainedAlgorithmicMedia":              c2pa.DigitalSourceTypeTrainedAlgorithmicMedia,
		"compositeWithTrainedAlgorithmicMedia": iptcDigitalSourceTypePrefix + "compositeWithTrainedAlgorithmicMedia",
		"https://example.com/x":                "https://example.com/x",
	}
	for in, want := range cases {
		if got := digitalSourceTypeURL(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
