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
	Present bool `json:"present"`
	// Attribution says who the manifest is a claim ABOUT: "asset" when the
	// file's own structure associates it, "embedded" when the file associates
	// it with something it CARRIES (a PDF object-level manifest, spec §A.4.3),
	// "unknown" when nothing places it at all. For the latter two, SignedBy is
	// not the file's signer — it belongs to the resource the manifest describes,
	// and reporting it as the file's is the mistake this field exists to
	// prevent. Omitted when there is no manifest.
	Attribution    string     `json:"attribution,omitempty"`
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
	Valid               bool       `json:"valid"`
	ActiveManifestLabel string     `json:"active_manifest_label,omitempty"`
	SignedAt            *time.Time `json:"signed_at,omitempty"` // from a VERIFIED timestamp
	// VerifiedSigner is the signer's identity once PROVEN — the claim signature
	// verified and the chain reached a trust anchor. Empty otherwise. This is the
	// field to trust; Signers below is only what the file presented.
	VerifiedSigner string `json:"verified_signer,omitempty"`
	// Signers is the signer chain's subject CNs, leaf first, AS PRESENTED in the
	// manifest — populated whether or not the chain verified, so a name read from
	// it is a claim.
	Signers []string `json:"signers,omitempty"`
	// Binding is what the hard binding proved about THESE bytes, which is a
	// different question from Valid: "verified" (a hard binding covered them and
	// held), "failed" (it covered them and did not hold), "unevaluated" (one
	// exists but this call did not check it against these bytes — a PDF manifest
	// attached to an embedded object, an asset past the scan cap, a fragmented
	// asset without its fragments) or "none" (nothing bound the asset at all).
	// A manifest can be valid with an unevaluated binding, and can have a
	// verified binding while failing on trust, so read both.
	Binding string `json:"binding"`
	// SoftBindings are the active manifest's soft bindings (c2pa.soft-binding):
	// perceptual identifiers that let a re-encoded or stripped copy be matched
	// back to this manifest. They are REPORTED, never checked — see
	// SoftBindingReport — so they say nothing about Valid or Binding.
	SoftBindings []SoftBindingReport `json:"soft_bindings,omitempty"`
	// Identities are the active manifest's CAWG identity assertions: named
	// actors who signed over the content with their own credentials. Read
	// each entry's Name for who was PROVEN and PresentedAs for who was merely
	// claimed — the same split as VerifiedSigner and Signers above. An identity
	// says the actor VOUCHED for these assertions; it conveys neither
	// attribution nor ownership. Identities of ingredient manifests are
	// validated but not listed here.
	Identities []IdentityReport `json:"identities,omitempty"`
	Detect     DetectResult     `json:"detect"` // the unverified claims, for convenience
	Statuses   []StatusInfo     `json:"statuses"`
}

// VerifyOptions is the common subset of c2pa.ValidateOption controls exposed by
// the CLI and MCP server.
type VerifyOptions struct {
	// SigningTrustPEM, when non-empty, overrides the embedded signing-anchor
	// trust pool with the certificates in this PEM bundle.
	SigningTrustPEM []byte
	// TimestampTrustPEM, when non-empty, overrides the embedded TSA trust pool.
	TimestampTrustPEM []byte
	// IdentityTrustPEM, when non-empty, anchors CAWG X.509 identity credentials
	// — the certificate authorities whose credentials PROVE a named actor.
	// There is no default: CAWG publishes no list, so without this every
	// identity is well-formed and its actor unproven.
	IdentityTrustPEM []byte
	// IdentityIssuers are the identity claims aggregators to believe, by DID.
	// Empty means issuer trust is not evaluated, which is the honest default;
	// naming any means a credential from an aggregator NOT named is a failure.
	IdentityIssuers []string
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
	return verifyWith(ctx, container, r, cfg...), nil
}

// verifyWith runs the validator with ready-made options and shapes its result.
// Verify and Sign both go through it, so a signed asset is reported exactly as
// verify would report it.
func verifyWith(ctx context.Context, container c2pa.Container, r io.Reader, cfg ...c2pa.ValidateOption) VerifyResult {
	res := c2pa.Validate(ctx, container, r, cfg...)

	out := VerifyResult{
		Valid:               res.Valid,
		ActiveManifestLabel: res.ActiveManifestLabel,
		Binding:             res.Binding.String(),
		SoftBindings:        toSoftBindingReports(res.SoftBindings),
		Identities:          toIdentityReports(res.Identities),
		Detect:              toDetectResult(res.Info),
	}
	if !res.SignedAt.IsZero() {
		t := res.SignedAt
		out.SignedAt = &t
	}
	out.VerifiedSigner = res.VerifiedSigner()
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
	return out
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
	if len(o.IdentityTrustPEM) > 0 {
		pool, err := poolFromPEM(o.IdentityTrustPEM, "identity trust")
		if err != nil {
			return nil, err
		}
		opts = append(opts, c2pa.WithIdentityTrust(pool))
	}
	// Only when the caller actually named an aggregator. c2pa.WithIdentityIssuers()
	// with no DIDs means "trust NO aggregator" and fails every aggregation
	// credential — so the guard belongs here, at the call site, and never on
	// the arguments.
	if len(o.IdentityIssuers) > 0 {
		opts = append(opts, c2pa.WithIdentityIssuers(o.IdentityIssuers...))
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
		Attribution:    string(info.Attribution),
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
		writeField(&b, "Signed at (claimed)", d.SignedAt.Format(timeLayout))
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
	writeField(&b, "Content binding", bindingSummary(v.Binding))
	if v.VerifiedSigner != "" {
		writeField(&b, "Signed by (verified)", v.VerifiedSigner)
	}
	if len(v.Signers) > 0 {
		writeField(&b, "Signer chain (as presented)", strings.Join(v.Signers, " <- "))
	}
	if v.SignedAt != nil {
		writeField(&b, "Signed at (verified)", v.SignedAt.Format(timeLayout))
	}
	if v.Detect.AIGenerated {
		writeField(&b, "AI generated", "yes")
	}
	for _, sb := range v.SoftBindings {
		writeField(&b, "Soft binding", sb.summarize())
	}
	for _, id := range v.Identities {
		writeField(&b, "Vouched for by", id.summarize())
	}
	writeStatuses(&b, v.Statuses)
	return strings.TrimRight(b.String(), "\n")
}

// writeStatuses appends the per-step status list, which is the bulk of a
// verify summary and the part that says WHY a verdict came out as it did.
func writeStatuses(b *strings.Builder, statuses []StatusInfo) {
	if len(statuses) == 0 {
		return
	}
	b.WriteString("Statuses:\n")
	for _, s := range statuses {
		line := fmt.Sprintf("  [%s] %s", s.Severity, s.Code)
		if s.Explanation != "" {
			line += " - " + s.Explanation
		}
		b.WriteString(line + "\n")
	}
}

// bindingSummary spells out a binding state, because "unevaluated" is the one a
// reader guesses wrong: it is neither a pass nor a failure, and a manifest can
// be valid while nothing checked whether these are the bytes it signed.
func bindingSummary(state string) string {
	switch state {
	case "verified":
		return "verified (these are the signed bytes)"
	case "failed":
		return "failed (these are NOT the signed bytes)"
	case "unevaluated":
		return "unevaluated (nothing here proves these are the signed bytes)"
	case "none":
		return "none (no hard binding covers this asset)"
	}
	return state
}

// timeLayout is how summaries print verified and claimed times.
const timeLayout = time.RFC3339

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
