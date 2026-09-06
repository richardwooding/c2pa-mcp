package analyze

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/richardwooding/c2pa"
)

// largePDF is a minimal, valid PDF whose one content stream is padding bytes
// long, so the store a signer appends lands past c2pa.MaxScan.
func largePDF(padding int) []byte {
	var b bytes.Buffer
	offsets := make([]int, 5)
	b.WriteString("%PDF-1.4\n")
	obj := func(n int, body string) {
		offsets[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Contents 4 0 R >>")
	offsets[4] = b.Len()
	fmt.Fprintf(&b, "4 0 obj\n<< /Length %d >>\nstream\n", padding)
	b.Write(bytes.Repeat([]byte{' '}, padding))
	b.WriteString("\nendstream\nendobj\n")
	xref := b.Len()
	b.WriteString("xref\n0 5\n0000000000 65535 f \n")
	for _, off := range offsets[1:] {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

// TestSign_AutoSeesStorePastReadCap: deciding created/opened must use the
// validator's scan depth, not Read's 16 MiB triage cap — a signed PDF larger
// than that carries its store at the very end.
func TestSign_AutoSeesStorePastReadCap(t *testing.T) {
	s, _ := testSigner(t, nil)
	ctx := context.Background()
	var first bytes.Buffer
	res, err := s.Sign(ctx, c2pa.PDF, bytes.NewReader(largePDF(c2pa.MaxScan+4096)), &first, SignRequest{Title: "big"})
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}
	if res.Action != c2pa.ActionCreated {
		t.Fatalf("first action = %s", res.Action)
	}
	// Read alone does not see the store; the auto decision still must.
	if c2pa.Read(ctx, c2pa.PDF, bytes.NewReader(first.Bytes())).Present {
		t.Skip("Read saw the store: the fixture is not large enough to exercise the cap")
	}
	var second bytes.Buffer
	res, err = s.Sign(ctx, c2pa.PDF, bytes.NewReader(first.Bytes()), &second, SignRequest{Title: "bigger"})
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}
	if res.Action != c2pa.ActionOpened || !res.ChainedPriorManifest {
		t.Fatalf("second sign did not chain: %+v", res)
	}
}
