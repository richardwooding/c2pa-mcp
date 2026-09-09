package analyze

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/richardwooding/c2pa"
)

// CAWG identities — who vouched for an asset, as opposed to which tool wrote it.
//
// A c2pa.claim says which software produced a manifest. A cawg.identity
// assertion is a named actor's OWN signature, with their own credential, over
// some of that manifest's assertions — always the hard binding, so the actor
// vouches for the content bytes too. There are two kinds: an X.509 credential
// (sig_type cawg.x509.cose) and an identity claims aggregation credential
// (cawg.identity_claims_aggregation), a verifiable credential in which an
// aggregator lists identity signals it checked — a social account, a document
// verification, an affiliation.
//
// The whole difficulty here is saying exactly what is known and no more. CAWG
// is explicit that an identity assertion "SHOULD NOT be construed to convey
// either attribution or ownership of a C2PA asset", and an aggregator attests
// only that the actor PRESENTED signals to it and PRESENTED this asset to it —
// never that they made the thing. So nothing in this package says "created by".
// It says vouched for, and it separates what was presented from what was
// proven exactly as VerifyResult separates Signers from VerifiedSigner.

var (
	// ErrIdentityRole is returned for a role that is not a CAWG label.
	ErrIdentityRole = errors.New(`identity role must be a label such as "cawg.creator" or "com.example.reviewer"`)
	// ErrIdentityCredential is returned when identity roles or references are
	// asked for without an identity key and certificate to sign them with.
	ErrIdentityCredential = errors.New("identity roles and references need --identity-key and --identity-cert")
)

// isIdentityLabel reports whether s is a CAWG label: dot-separated segments,
// each starting alphanumeric, at least two of them ("cawg.creator"). The c2pa
// library enforces the same shape; checking here lets the error name the flag
// the user typed instead of surfacing from inside the signing pipeline.
func isIdentityLabel(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || !isAlnum(rune(p[0])) {
			return false
		}
		for _, r := range p {
			if !isAlnum(r) && r != '_' && r != '-' {
				return false
			}
		}
	}
	return true
}

func isAlnum(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// identityInfoFor builds what Sign writes as the named actor's relationship to
// the asset, or the zero value when nothing was asked for.
//
// It refuses roles and references without an identity credential rather than
// letting the library refuse them later: the message can name the flags. The
// library re-checks everything (a reference must name an assertion actually
// being written, must not be the hard binding, and must not repeat), and those
// are the checks only it can make.
func identityInfoFor(roles, references []string, hasCredential bool) (c2pa.IdentityInfo, error) {
	if len(roles) == 0 && len(references) == 0 {
		return c2pa.IdentityInfo{}, nil
	}
	if !hasCredential {
		return c2pa.IdentityInfo{}, ErrIdentityCredential
	}
	for _, r := range roles {
		if !isIdentityLabel(r) {
			return c2pa.IdentityInfo{}, fmt.Errorf("%w: got %q", ErrIdentityRole, r)
		}
	}
	return c2pa.IdentityInfo{Roles: roles, References: references}, nil
}

// IdentityReport is the JSON-serializable form of one c2pa.Identity a verifier
// FOUND: a named actor who signed over this manifest's content with their own
// credential.
//
// Read Name for who was PROVEN — it is empty unless Trusted, exactly as
// VerifyResult.VerifiedSigner is. PresentedAs, Issuer and VerifiedIdentities
// are what the manifest and the aggregator SAY, populated whether or not
// anything vouched for them, so a name read from those is a claim.
//
// None of it conveys attribution or ownership: an identity assertion means this
// actor signed over these assertions, and an aggregation credential means an
// aggregator says the actor showed it these signals and this asset.
type IdentityReport struct {
	// Label is the assertion label, "cawg.identity" or an instance form.
	Label string `json:"label"`
	// URI is "<manifest label>/<label>", where this identity's statuses are
	// recorded. They are NOT the claim's statuses even where the codes look
	// like it: claimSignature.validated and signingCredential.trusted are
	// reused here for the identity's own signature and chain.
	URI string `json:"uri"`
	// SigType is "cawg.x509.cose" for an X.509 credential, or
	// "cawg.identity_claims_aggregation" for an aggregator's.
	SigType string `json:"sig_type,omitempty"`
	// Roles are the actor's declared roles ("cawg.creator", …), AS PRESENTED.
	Roles []string `json:"roles,omitempty"`
	// Referenced lists the assertions the actor signed over, in payload order.
	// The hard binding is always among them, which is what makes the actor
	// vouch for the content bytes and not merely for some metadata.
	Referenced []string `json:"referenced,omitempty"`

	// Valid: the assertion is well-formed and its signature verifies. For an
	// aggregation credential it also requires an issuer that is trusted or not
	// evaluated — one ruled out by identity_issuers is a failure and leaves
	// this false even though the credential itself verified.
	Valid bool `json:"valid"`
	// Trusted: Valid, and the credential reached a root of trust — an X.509
	// chain anchored by identity_trust, or an aggregator DID named in
	// identity_issuers. Neither has a default, so this is false unless the
	// caller said whom to believe. Only then is the actor proven.
	Trusted bool `json:"trusted"`
	// Name is the actor's name, ONLY when Trusted; "" otherwise.
	Name string `json:"name,omitempty"`
	// PresentedAs is the identity certificate's subject as PRESENTED — a claim,
	// not a fact, until Trusted. Empty for an aggregation credential, which
	// carries no certificate.
	PresentedAs string `json:"presented_as,omitempty"`

	// Issuer is the aggregator's DID, AS PRESENTED (aggregation credentials
	// only). Only did:jwk is resolved; did:web — what some aggregators use — is
	// reported unsupported, which is a limit of this build rather than a defect
	// in the file.
	Issuer string `json:"issuer,omitempty"`
	// VerifiedIdentities are the signals the aggregator says it checked, AS
	// PRESENTED BY IT. The aggregator's word, proven only as far as the
	// aggregator is trusted.
	VerifiedIdentities []VerifiedIdentityReport `json:"verified_identities,omitempty"`

	// SignedAt is the signing time from a TRUSTED timestamp on the identity
	// signature, omitted when there is none. A missing value alongside a
	// timestamp in the file means the timestamp authority was not trusted.
	SignedAt *time.Time `json:"signed_at,omitempty"`
}

// VerifiedIdentityReport is one identity signal an aggregator vouched for, as
// presented by that aggregator.
type VerifiedIdentityReport struct {
	// Type is the kind of signal: "cawg.social_media",
	// "cawg.document_verification", "cawg.affiliation", "cawg.crypto_wallet", …
	Type string `json:"type,omitempty"`
	// Name and Username are how the actor appears to that provider.
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
	// URI locates the account, for a social-media or wallet signal.
	URI string `json:"uri,omitempty"`
	// VerifiedAt is when the aggregator says it checked the signal.
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	// ProviderID and ProviderName are the service the signal was checked with.
	ProviderID   string `json:"provider_id,omitempty"`
	ProviderName string `json:"provider_name,omitempty"`
}

// toIdentityReports shapes the library's identities for JSON.
func toIdentityReports(ids []c2pa.Identity) []IdentityReport {
	var out []IdentityReport
	for _, id := range ids {
		r := IdentityReport{
			Label:      id.Label,
			URI:        id.URI,
			SigType:    id.SigType,
			Roles:      id.Roles,
			Referenced: id.Referenced,
			Valid:      id.Valid,
			Trusted:    id.Trusted,
			Name:       id.Name(),
			Issuer:     id.Issuer,
		}
		// Chain is empty for an aggregation credential, and for an X.509 one
		// whose COSE carried no x5chain.
		if len(id.Chain) > 0 {
			r.PresentedAs = certName(id.Chain[0])
		}
		if !id.SignedAt.IsZero() {
			t := id.SignedAt
			r.SignedAt = &t
		}
		for _, vi := range id.VerifiedIdentities {
			v := VerifiedIdentityReport{
				Type:         vi.Type,
				Name:         vi.Name,
				Username:     vi.Username,
				URI:          vi.URI,
				ProviderID:   vi.Provider.ID,
				ProviderName: vi.Provider.Name,
			}
			if !vi.VerifiedAt.IsZero() {
				t := vi.VerifiedAt
				v.VerifiedAt = &t
			}
			r.VerifiedIdentities = append(r.VerifiedIdentities, v)
		}
		out = append(out, r)
	}
	return out
}

// claimedName is the first name or username an aggregator attached to a signal
// it says it checked, or "". The aggregator's word, never proof.
func (r IdentityReport) claimedName() string {
	for _, vi := range r.VerifiedIdentities {
		if vi.Name != "" {
			return vi.Name
		}
		if vi.Username != "" {
			return vi.Username
		}
	}
	return ""
}

// shortDID abbreviates a DID for a one-line summary. A did:jwk embeds a whole
// public key, so printing it whole buries the sentence it appears in; the full
// value is always in the report's issuer field.
func shortDID(did string) string {
	const keep = 24
	if len(did) <= keep {
		return did
	}
	return did[:keep] + "…"
}

// summarize renders one identity as a single line, and never lets it read as
// attribution. A reader who sees a name beside a VALID verdict will otherwise
// take it as "made by", which is the one reading CAWG rules out.
func (r IdentityReport) summarize() string {
	var b bytes.Buffer

	switch claimed := r.claimedName(); {
	case r.Trusted && r.Name != "":
		fmt.Fprintf(&b, "%s (PROVEN)", r.Name)
	case r.PresentedAs != "":
		fmt.Fprintf(&b, "%s (presented, unproven)", r.PresentedAs)
	case claimed != "":
		// An aggregation credential names nobody itself; the name belongs to a
		// signal the aggregator says it checked, so it is labelled as theirs.
		fmt.Fprintf(&b, "%s (%s says so, unproven)", claimed, shortDID(r.Issuer))
	case r.Issuer != "":
		fmt.Fprintf(&b, "an actor vouched for by %s (unproven)", shortDID(r.Issuer))
	default:
		b.WriteString("an unnamed actor")
	}

	if !r.Valid {
		b.WriteString(" - the identity assertion did NOT validate")
		return b.String()
	}
	b.WriteString(" vouches for ")
	if len(r.Referenced) > 0 {
		b.WriteString(strings.Join(r.Referenced, ", "))
	} else {
		b.WriteString("the content")
	}
	if len(r.Roles) > 0 {
		fmt.Fprintf(&b, " as %s", strings.Join(r.Roles, ", "))
	}
	if !r.Trusted {
		b.WriteString(" - signature genuine, actor NOT proven")
	}
	return b.String()
}
