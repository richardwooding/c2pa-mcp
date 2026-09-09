package analyze

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"image/png"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-mcp/internal/testpki"
)

// CAWG identity: who vouched for an asset.
//
// The X.509 half is tested end to end — sign with a named actor's credential,
// then read it back through the real verify path. The aggregation half is
// tested at the shaping layer with a hand-built c2pa.Identity, because this
// repo cannot WRITE an aggregation credential (only an aggregator can) and
// vendoring c2pa-rs's 259 KB fixture would only re-test the library's parser,
// which the library already tests against it. What is ours to get right is the
// conversion, and that is what these exercise.

// identitySigner returns a Signer that also writes a cawg.identity assertion,
// plus the actor's credential so a test can anchor it.
func identitySigner(t *testing.T) (*Signer, testpki.Credentials) {
	t.Helper()
	actor, err := testpki.SelfSigned("Corpus Cat")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := testSigner(t, func(cfg *SignerConfig) {
		cfg.IdentityKeyPEM = actor.KeyPEM()
		cfg.IdentityCertPEM = actor.CertPEM()
	})
	return signer, actor
}

func identityScene(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, isccScene()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// identityFields flattens the scalar fields worth asserting, so one loop
// replaces a chain of branches and every wrong field is reported.
func identityFields(id IdentityReport) map[string]string {
	return map[string]string{
		"label":        id.Label,
		"sig type":     id.SigType,
		"valid":        strconv.FormatBool(id.Valid),
		"trusted":      strconv.FormatBool(id.Trusted),
		"name":         id.Name,
		"presented as": id.PresentedAs,
		"issuer":       id.Issuer,
		"roles":        strings.Join(id.Roles, ","),
	}
}

// TestSignAndReportIdentity is the end-to-end shape: sign as a named actor,
// then read the identity back out of the signed asset the way verify does.
func TestSignAndReportIdentity(t *testing.T) {
	signer, actor := identitySigner(t)
	asset := identityScene(t)

	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(asset), &out,
		SignRequest{Title: "vouched", IdentityRoles: []string{c2pa.RoleCreator}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.Identity == nil || res.Identity.Name != "Corpus Cat" ||
		!equalStrings(res.Identity.Roles, []string{c2pa.RoleCreator}) {
		t.Fatalf("SignResult.Identity = %+v", res.Identity)
	}

	// The signer's own read-back: genuine signature, actor NOT proven, because
	// this call configured no identity anchors.
	if len(res.Verify.Identities) != 1 {
		t.Fatalf("read back %d identities, want 1", len(res.Verify.Identities))
	}
	assertFields(t, identityFields(res.Verify.Identities[0]), map[string]string{
		"label":        "cawg.identity",
		"sig type":     "cawg.x509.cose",
		"valid":        "true",
		"trusted":      "false", // no identity anchors configured
		"name":         "",      // proven name, and nothing proved it
		"presented as": "Corpus Cat",
		"roles":        c2pa.RoleCreator,
	})
	if line := res.Verify.Identities[0].summarize(); !strings.Contains(line, "presented, unproven") ||
		!strings.Contains(line, "NOT proven") {
		t.Errorf("summary must not read as attribution: %q", line)
	}

	// Anchoring the actor's own CA proves them — the same flip VerifiedSigner
	// makes for the claim signer.
	anchored, err := Verify(context.Background(), c2pa.PNG, bytes.NewReader(out.Bytes()),
		VerifyOptions{IdentityTrustPEM: actor.CertPEM()})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchored.Identities) != 1 {
		t.Fatalf("anchored: %d identities", len(anchored.Identities))
	}
	assertFields(t, identityFields(anchored.Identities[0]), map[string]string{
		"trusted":      "true",
		"name":         "Corpus Cat", // proven, so Name answers
		"presented as": "Corpus Cat",
	})
	if line := anchored.Identities[0].summarize(); !strings.Contains(line, "PROVEN") {
		t.Errorf("an anchored identity should say so: %q", line)
	}
}

// TestIdentityDoesNotVouchForTheClaim: identity statuses are recorded at
// "<manifest>/<assertion label>" and REUSE core codes like
// claimSignature.validated. A reader keying off codes alone would report the
// identity's success as the claim signer's.
func TestIdentityDoesNotVouchForTheClaim(t *testing.T) {
	signer, actor := identitySigner(t)
	var out bytes.Buffer
	if _, err := signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(identityScene(t)), &out,
		SignRequest{IdentityRoles: []string{c2pa.RoleCreator}}); err != nil {
		t.Fatal(err)
	}

	// Anchor ONLY the actor, never the claim signer's chain.
	res, err := Verify(context.Background(), c2pa.PNG, bytes.NewReader(out.Bytes()),
		VerifyOptions{IdentityTrustPEM: actor.CertPEM()})
	if err != nil {
		t.Fatal(err)
	}
	if res.VerifiedSigner != "" {
		t.Errorf("a proven ACTOR must not make the claim signer verified: %q", res.VerifiedSigner)
	}
	if len(res.Identities) != 1 || !res.Identities[0].Trusted {
		t.Fatalf("identity should be trusted: %+v", res.Identities)
	}
	// And the identity's statuses live at their own URI, not the manifest's.
	if uri := res.Identities[0].URI; !strings.HasPrefix(uri, res.ActiveManifestLabel+"/") {
		t.Errorf("identity URI = %q, want a child of %q", uri, res.ActiveManifestLabel)
	}
}

// TestIdentityIssuersNotConfigured pins the trap: c2pa.WithIdentityIssuers()
// with no DIDs means "trust NO aggregator" and fails every aggregation
// credential, so the option must not be passed at all when the caller named
// none. Verified through the option builder, which is where the guard lives.
func TestIdentityIssuersNotConfigured(t *testing.T) {
	for name, opts := range map[string]VerifyOptions{
		"nil slice":   {IdentityIssuers: nil},
		"empty slice": {IdentityIssuers: []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := opts.toValidateOptions()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Errorf("%d options built; naming no issuer must leave issuer trust unevaluated", len(got))
			}
		})
	}

	got, err := VerifyOptions{IdentityIssuers: []string{"did:jwk:abc"}}.toValidateOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("naming an issuer should build the option, got %d", len(got))
	}
}

// TestIdentityRefusals: every way of asking for an identity that cannot be
// written must be an error naming the reason, never a quiet sign without one.
func TestIdentityRefusals(t *testing.T) {
	plain, _ := testSigner(t, nil) // no identity credential
	withIdentity, _ := identitySigner(t)
	asset := identityScene(t)

	cases := []struct {
		name   string
		signer *Signer
		req    SignRequest
		want   error
	}{
		{"roles without a credential", plain, SignRequest{IdentityRoles: []string{c2pa.RoleCreator}}, ErrIdentityCredential},
		{"references without a credential", plain, SignRequest{IdentityReferences: []string{"c2pa.actions.v2"}}, ErrIdentityCredential},
		{"role that is not a label", withIdentity, SignRequest{IdentityRoles: []string{"creator"}}, ErrIdentityRole},
		{"role with a bad segment", withIdentity, SignRequest{IdentityRoles: []string{"cawg..creator"}}, ErrIdentityRole},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := tc.signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(asset), &out, tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if out.Len() != 0 {
				t.Error("a refused sign wrote bytes")
			}
		})
	}

	// The library owns the checks only it can make; the message must still
	// reach the user rather than being swallowed.
	var out bytes.Buffer
	_, err := withIdentity.Sign(context.Background(), c2pa.PNG, bytes.NewReader(asset), &out,
		SignRequest{IdentityReferences: []string{"c2pa.hash.data"}})
	if err == nil || !strings.Contains(err.Error(), "hard binding") {
		t.Errorf("referencing the hard binding should be refused with a reason, got %v", err)
	}
}

// TestSignWithoutIdentityWritesNone: the default is unchanged.
func TestSignWithoutIdentityWritesNone(t *testing.T) {
	signer, _ := testSigner(t, nil)
	var out bytes.Buffer
	res, err := signer.Sign(context.Background(), c2pa.PNG, bytes.NewReader(identityScene(t)), &out, SignRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Identity != nil || len(res.Verify.Identities) != 0 {
		t.Errorf("wrote an identity nobody asked for: %+v / %+v", res.Identity, res.Verify.Identities)
	}
}

// TestIdentityReportShapesAggregation covers what this repo cannot write and
// therefore cannot round-trip: an identity claims aggregation credential, where
// there is no certificate at all and every name is the AGGREGATOR's word.
func TestIdentityReportShapesAggregation(t *testing.T) {
	verified := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	reports := toIdentityReports([]c2pa.Identity{{
		Label:      "cawg.identity",
		URI:        "urn:c2pa:x/cawg.identity",
		SigType:    "cawg.identity_claims_aggregation",
		Issuer:     "did:jwk:eyJrdHkiOiJPS1AifQ",
		Referenced: []string{"c2pa.hash.data"},
		Valid:      true, // credential verified; issuer trust not evaluated
		VerifiedIdentities: []c2pa.VerifiedIdentity{{
			Type:       "cawg.social_media",
			Name:       "Corpus Cat",
			Username:   "corpuscat",
			URI:        "https://social.example/corpuscat",
			VerifiedAt: verified,
			Provider:   c2pa.IdentityProvider{ID: "https://social.example", Name: "Social Example"},
		}},
	}})
	if len(reports) != 1 {
		t.Fatalf("%d reports", len(reports))
	}
	r := reports[0]
	assertFields(t, identityFields(r), map[string]string{
		"sig type":     "cawg.identity_claims_aggregation",
		"valid":        "true",
		"trusted":      "false",
		"name":         "", // Name() is empty unless Trusted, whoever the aggregator names
		"presented as": "", // no certificate: an aggregation credential carries none
		"issuer":       "did:jwk:eyJrdHkiOiJPS1AifQ",
	})
	if len(r.VerifiedIdentities) != 1 {
		t.Fatalf("%d verified identities", len(r.VerifiedIdentities))
	}
	vi := r.VerifiedIdentities[0]
	if vi.Name != "Corpus Cat" || vi.Username != "corpuscat" || vi.ProviderName != "Social Example" ||
		vi.VerifiedAt == nil || !vi.VerifiedAt.Equal(verified) {
		t.Errorf("verified identity = %+v", vi)
	}
	// The aggregator's name must never read as a proven one, and the line must
	// attribute it to the aggregator rather than stating it flatly. The DID is
	// abbreviated because a did:jwk embeds a whole public key.
	line := r.summarize()
	switch {
	case strings.Contains(line, "PROVEN"):
		t.Errorf("an unproven identity claims to be proven: %q", line)
	case !strings.Contains(line, "Corpus Cat"):
		t.Errorf("summary should name who the aggregator says it is: %q", line)
	case !strings.Contains(line, "says so, unproven"):
		t.Errorf("summary should attribute the name to the aggregator: %q", line)
	case strings.Contains(line, r.Issuer):
		t.Errorf("the full DID buries the sentence; abbreviate it: %q", line)
	}
}

// TestIdentitySummaryNeverClaimsAuthorship is the wording guard. CAWG: an
// identity assertion "SHOULD NOT be construed to convey either attribution or
// ownership", so no rendering of one may say the actor made the thing.
func TestIdentitySummaryNeverClaimsAuthorship(t *testing.T) {
	forbidden := []string{"created by", "author", "owner", "owned by", "made by"}
	reports := toIdentityReports([]c2pa.Identity{
		{Label: "cawg.identity", SigType: "cawg.x509.cose", Valid: true, Roles: []string{c2pa.RoleCreator},
			Referenced: []string{"c2pa.hash.data"}, Chain: []*x509.Certificate{{Subject: pkix.Name{CommonName: "Corpus Cat"}}}},
		{Label: "cawg.identity__1", SigType: "cawg.x509.cose", Valid: false},
	})
	for _, r := range reports {
		line := strings.ToLower(r.summarize())
		for _, word := range forbidden {
			if strings.Contains(line, word) {
				t.Errorf("summary %q uses %q, which claims authorship", line, word)
			}
		}
		if !strings.Contains(line, "vouches for") && !strings.Contains(line, "did not validate") {
			t.Errorf("summary should say what the actor vouched for: %q", line)
		}
	}
}

// TestIdentityReportHandlesMissingChain: an X.509 identity whose COSE carried
// no x5chain has no certificate to present, and must not panic.
func TestIdentityReportHandlesMissingChain(t *testing.T) {
	r := toIdentityReports([]c2pa.Identity{{Label: "cawg.identity", SigType: "cawg.x509.cose"}})
	if len(r) != 1 || r[0].PresentedAs != "" {
		t.Fatalf("report = %+v", r)
	}
	if line := r[0].summarize(); line == "" {
		t.Error("an identity with nothing to present still needs a line")
	}
}

// equalStrings reports whether two string slices match element for element.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
