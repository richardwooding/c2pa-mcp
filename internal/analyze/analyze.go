package analyze

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/richardwooding/c2pa"
)

// DetectResult is the JSON-serializable form of c2pa.Read's output: what a file
// CLAIMS about its provenance, unverified (like EXIF or an unverified From:
// header). SignedBy and SignedAt are claims, not proof.
type DetectResult struct {
	Present        bool       `json:"present"`
	ClaimGenerator string     `json:"claim_generator,omitempty"`
	Title          string     `json:"title,omitempty"`
	Format         string     `json:"format,omitempty"`
	AIGenerated    bool       `json:"ai_generated"`
	SignedBy       string     `json:"signed_by,omitempty"`
	SignedAt       *time.Time `json:"signed_at,omitempty"`
}

// StatusInfo is the JSON-serializable form of a c2pa.StatusEntry.
type StatusInfo struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	URI         string `json:"uri,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}

// VerifyResult is the JSON-serializable form of c2pa.Validate's output. Valid is
// true iff no failure-severity status was recorded, mirroring the library.
type VerifyResult struct {
	Valid               bool         `json:"valid"`
	ActiveManifestLabel string       `json:"active_manifest_label,omitempty"`
	SignedAt            *time.Time   `json:"signed_at,omitempty"` // from a VERIFIED timestamp
	Signers             []string     `json:"signers,omitempty"`   // signer chain subject CNs, leaf first
	Detect              DetectResult `json:"detect"`              // the unverified claims, for convenience
	Statuses            []StatusInfo `json:"statuses"`
}

// VerifyOptions is the common subset of c2pa.ValidateOption controls exposed by
// the CLI and MCP server.
type VerifyOptions struct {
	// SigningTrustPEM, when non-empty, overrides the embedded signing-anchor
	// trust pool with the certificates in this PEM bundle.
	SigningTrustPEM []byte
	// TimestampTrustPEM, when non-empty, overrides the embedded TSA trust pool.
	TimestampTrustPEM []byte
	// OnlineRevocation enables OCSP/CRL revocation checks (network, soft-fail).
	OnlineRevocation bool
	// MaxScan overrides how many leading bytes the validator reads (0 = default).
	MaxScan int
}

// Detect runs the fast, unverified reader over r.
func Detect(ctx context.Context, container c2pa.Container, r io.Reader) DetectResult {
	return toDetectResult(c2pa.Read(ctx, container, r))
}

// Verify runs the full validator over r with the given options.
func Verify(ctx context.Context, container c2pa.Container, r io.Reader, opts VerifyOptions) (VerifyResult, error) {
	cfg, err := opts.toValidateOptions()
	if err != nil {
		return VerifyResult{}, err
	}
	res := c2pa.Validate(ctx, container, r, cfg...)

	out := VerifyResult{
		Valid:               res.Valid,
		ActiveManifestLabel: res.ActiveManifestLabel,
		Detect:              toDetectResult(res.Info),
	}
	if !res.SignedAt.IsZero() {
		t := res.SignedAt
		out.SignedAt = &t
	}
	for _, cert := range res.SignerChain {
		out.Signers = append(out.Signers, certName(cert))
	}
	for _, s := range res.Statuses {
		si := StatusInfo{
			Code:        string(s.Code),
			Severity:    severityString(s.Severity),
			URI:         s.URI,
			Explanation: s.Explanation,
		}
		if s.Err != nil {
			if si.Explanation == "" {
				si.Explanation = s.Err.Error()
			} else {
				si.Explanation = fmt.Sprintf("%s: %s", si.Explanation, s.Err)
			}
		}
		out.Statuses = append(out.Statuses, si)
	}
	return out, nil
}

func (o VerifyOptions) toValidateOptions() ([]c2pa.ValidateOption, error) {
	var opts []c2pa.ValidateOption
	if len(o.SigningTrustPEM) > 0 {
		pool, err := poolFromPEM(o.SigningTrustPEM, "signing trust")
		if err != nil {
			return nil, err
		}
		opts = append(opts, c2pa.WithSigningTrust(pool))
	}
	if len(o.TimestampTrustPEM) > 0 {
		pool, err := poolFromPEM(o.TimestampTrustPEM, "timestamp trust")
		if err != nil {
			return nil, err
		}
		opts = append(opts, c2pa.WithTimestampTrust(pool))
	}
	if o.OnlineRevocation {
		opts = append(opts, c2pa.WithOnlineRevocation(true))
	}
	if o.MaxScan > 0 {
		opts = append(opts, c2pa.WithMaxScan(o.MaxScan))
	}
	return opts, nil
}

func poolFromPEM(pem []byte, what string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificates found in PEM bundle", what)
	}
	return pool, nil
}

func toDetectResult(info c2pa.Info) DetectResult {
	res := DetectResult{
		Present:        info.Present,
		ClaimGenerator: info.ClaimGenerator,
		Title:          info.Title,
		Format:         info.Format,
		AIGenerated:    info.AIGenerated,
		SignedBy:       info.SignedBy,
	}
	if !info.SignedAt.IsZero() {
		t := info.SignedAt
		res.SignedAt = &t
	}
	return res
}

func certName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return cert.Subject.String()
}

func severityString(s c2pa.Severity) string {
	switch s {
	case c2pa.SeveritySuccess:
		return "success"
	case c2pa.SeverityFailure:
		return "failure"
	case c2pa.SeverityInformational:
		return "informational"
	default:
		return "unknown"
	}
}

// Summary renders a Detect result as a short human-readable block.
func (d DetectResult) Summary() string {
	if !d.Present {
		return "No C2PA manifest found (the file makes no provenance claims)."
	}
	var b strings.Builder
	b.WriteString("C2PA manifest present (UNVERIFIED claims):\n")
	writeField(&b, "Claim generator", d.ClaimGenerator)
	writeField(&b, "Title", d.Title)
	writeField(&b, "Format", d.Format)
	writeField(&b, "AI generated", boolStr(d.AIGenerated))
	writeField(&b, "Signed by (claimed)", d.SignedBy)
	if d.SignedAt != nil {
		writeField(&b, "Signed at (claimed)", d.SignedAt.Format(time.RFC3339))
	}
	return strings.TrimRight(b.String(), "\n")
}

// Summary renders a Verify result as a short human-readable block.
func (v VerifyResult) Summary() string {
	var b strings.Builder
	if v.Valid {
		b.WriteString("VALID: C2PA validation passed (no failures).\n")
	} else {
		b.WriteString("INVALID: C2PA validation found at least one failure.\n")
	}
	writeField(&b, "Active manifest", v.ActiveManifestLabel)
	if len(v.Signers) > 0 {
		writeField(&b, "Signer chain", strings.Join(v.Signers, " <- "))
	}
	if v.SignedAt != nil {
		writeField(&b, "Signed at (verified)", v.SignedAt.Format(time.RFC3339))
	}
	if v.Detect.AIGenerated {
		writeField(&b, "AI generated", "yes")
	}
	if len(v.Statuses) > 0 {
		b.WriteString("Statuses:\n")
		for _, s := range v.Statuses {
			line := fmt.Sprintf("  [%s] %s", s.Severity, s.Code)
			if s.Explanation != "" {
				line += " - " + s.Explanation
			}
			b.WriteString(line + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func writeField(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, "  %s: %s\n", label, value)
}

func boolStr(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
