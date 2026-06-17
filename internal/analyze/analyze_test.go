package analyze

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/richardwooding/c2pa"
)

const fixture = "../../testdata/c2pa_signed.jpg"

func readFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestOpen_Sniff(t *testing.T) {
	jpeg := readFixture(t)
	png := append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0}, 16)...)

	tests := []struct {
		name    string
		in      Input
		want    c2pa.Container
		wantErr error
	}{
		{"jpeg stdin", Input{Stdin: bytes.NewReader(jpeg)}, c2pa.JPEG, nil},
		{"png stdin", Input{Stdin: bytes.NewReader(png)}, c2pa.PNG, nil},
		{"base64 jpeg", Input{Base64: base64.StdEncoding.EncodeToString(jpeg)}, c2pa.JPEG, nil},
		{"unsupported", Input{Stdin: bytes.NewReader([]byte("GIF89a............"))}, "", ErrUnsupportedFormat},
		{"empty", Input{Stdin: bytes.NewReader(nil)}, "", ErrUnsupportedFormat},
		{"no source", Input{}, "", ErrNoSource},
		{"multiple sources", Input{Path: "x", Base64: "y"}, "", ErrMultipleSources},
		{"bad base64", Input{Base64: "!!!not-base64!!!"}, "", nil}, // error checked separately below
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container, r, closer, err := Open(context.Background(), tt.in, nil)
			if closer != nil {
				defer func() { _ = closer() }()
			}
			if tt.name == "bad base64" {
				if err == nil {
					t.Fatal("expected an error decoding bad base64")
				}
				return
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if container != tt.want {
				t.Fatalf("container = %q, want %q", container, tt.want)
			}
			// Sniffing must not consume bytes: the magic should still be readable.
			head := make([]byte, 3)
			if _, err := io.ReadFull(r, head); err != nil {
				t.Fatalf("read after sniff: %v", err)
			}
		})
	}
}

func TestOpen_Path(t *testing.T) {
	container, r, closer, err := Open(context.Background(), Input{Path: fixture}, nil)
	if err != nil {
		t.Fatalf("Open path: %v", err)
	}
	defer func() { _ = closer() }()
	if container != c2pa.JPEG {
		t.Fatalf("container = %q, want jpeg", container)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("read all: %v", err)
	}
}

func TestOpen_MissingPath(t *testing.T) {
	_, _, _, err := Open(context.Background(), Input{Path: filepath.Join(t.TempDir(), "nope.jpg")}, nil)
	if err == nil {
		t.Fatal("expected error opening missing file")
	}
}

func TestOpen_URL(t *testing.T) {
	jpeg := readFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jpeg)
	}))
	defer srv.Close()

	container, r, closer, err := Open(context.Background(), Input{URL: srv.URL}, srv.Client())
	if err != nil {
		t.Fatalf("Open url: %v", err)
	}
	defer func() { _ = closer() }()
	if container != c2pa.JPEG {
		t.Fatalf("container = %q, want jpeg", container)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, jpeg) {
		t.Fatalf("fetched %d bytes, want %d", len(got), len(jpeg))
	}
}

func TestOpen_URLNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, _, _, err := Open(context.Background(), Input{URL: srv.URL}, srv.Client())
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestDetect(t *testing.T) {
	res := Detect(context.Background(), c2pa.JPEG, bytes.NewReader(readFixture(t)))
	if !res.Present {
		t.Fatal("Present = false, want true")
	}
	if res.SignedBy != "C2PA Signer" {
		t.Fatalf("SignedBy = %q, want %q", res.SignedBy, "C2PA Signer")
	}
	if res.ClaimGenerator == "" {
		t.Fatal("ClaimGenerator is empty")
	}
	if res.SignedAt == nil {
		t.Fatal("SignedAt is nil, want the claimed timestamp")
	}
	if res.AIGenerated {
		t.Fatal("AIGenerated = true, want false")
	}
}

func TestVerify_Default(t *testing.T) {
	// Fixture is signed by the c2pa-rs test PKI, so against the production trust
	// list it is invalid, but the signature and hashes themselves are sound.
	res, err := Verify(context.Background(), c2pa.JPEG, bytes.NewReader(readFixture(t)), VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("Valid = true, want false (untrusted test PKI)")
	}
	if !hasStatus(res, "claimSignature.validated") {
		t.Fatal("expected claimSignature.validated success")
	}
	if !hasStatus(res, "signingCredential.untrusted") {
		t.Fatal("expected signingCredential.untrusted failure")
	}
	if !hasStatus(res, "assertion.dataHash.match") {
		t.Fatal("expected assertion.dataHash.match success")
	}
	if len(res.Signers) == 0 {
		t.Fatal("Signers is empty")
	}
}

func TestVerify_WithSigningTrust(t *testing.T) {
	// Anchor a pool at the fixture's own intermediate (the last cert in its
	// chain) and confirm the signing-credential step now trusts the chain.
	pem := signerChainPEM(t)
	res, err := Verify(context.Background(), c2pa.JPEG, bytes.NewReader(readFixture(t)), VerifyOptions{
		SigningTrustPEM: pem,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if hasStatus(res, "signingCredential.untrusted") {
		t.Fatal("signingCredential.untrusted still present after anchoring trust")
	}
	if !hasStatus(res, "signingCredential.trusted") {
		t.Fatal("expected signingCredential.trusted after anchoring trust")
	}
}

func TestVerify_BadSigningTrustPEM(t *testing.T) {
	_, err := Verify(context.Background(), c2pa.JPEG, bytes.NewReader(readFixture(t)), VerifyOptions{
		SigningTrustPEM: []byte("not a pem"),
	})
	if err == nil {
		t.Fatal("expected error for PEM with no certificates")
	}
}

func TestVerify_DataHashMismatch(t *testing.T) {
	data := readFixture(t)
	// Byte offset 150000 sits past the fixture's data-hash exclusion range
	// [20, 117293), so flipping it must surface a data-hash mismatch.
	data[150000] ^= 0xFF
	res, err := Verify(context.Background(), c2pa.JPEG, bytes.NewReader(data), VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("Valid = true, want false for tampered image data")
	}
	if !hasStatus(res, "assertion.dataHash.mismatch") {
		t.Fatalf("expected assertion.dataHash.mismatch, got statuses: %+v", res.Statuses)
	}
}

func hasStatus(res VerifyResult, code string) bool {
	for _, s := range res.Statuses {
		if s.Code == code {
			return true
		}
	}
	return false
}

// signerChainPEM PEM-encodes the fixture's signer chain so a test can anchor
// trust at the fixture's own intermediate.
func signerChainPEM(t *testing.T) []byte {
	t.Helper()
	r := c2pa.Validate(context.Background(), c2pa.JPEG, bytes.NewReader(readFixture(t)))
	if len(r.SignerChain) == 0 {
		t.Fatal("fixture produced no signer chain")
	}
	var buf bytes.Buffer
	for _, cert := range r.SignerChain {
		buf.WriteString("-----BEGIN CERTIFICATE-----\n")
		buf.WriteString(base64Block(cert.Raw))
		buf.WriteString("-----END CERTIFICATE-----\n")
	}
	// Sanity check the bundle parses.
	if !x509.NewCertPool().AppendCertsFromPEM(buf.Bytes()) {
		t.Fatal("generated PEM did not parse")
	}
	return buf.Bytes()
}

func base64Block(der []byte) string {
	const lineLen = 64
	enc := base64.StdEncoding.EncodeToString(der)
	var b bytes.Buffer
	for len(enc) > lineLen {
		b.WriteString(enc[:lineLen])
		b.WriteByte('\n')
		enc = enc[lineLen:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	return b.String()
}
