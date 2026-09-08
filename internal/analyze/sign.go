package analyze

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/richardwooding/c2pa"
)

// Errors a caller can branch on with errors.Is. Anything the c2pa library
// refuses (ErrManifestInvalid, ErrFragmentedBMFF, ErrSignerChain, ErrTimestamp,
// ...) is returned wrapped, so its sentinels work here too.
var (
	// ErrSigningKey is returned when the key PEM holds no usable private key.
	ErrSigningKey = errors.New("signing key: no usable private key in PEM")
	// ErrSigningCert is returned when the certificate PEM holds no certificate.
	ErrSigningCert = errors.New("signing certificate: no certificate in PEM")
	// ErrBadAction is returned for an action other than created, opened or auto.
	ErrBadAction = errors.New(`action must be "created", "opened" or "auto"`)
	// ErrOutputExists is returned by SignToFile when the output exists and
	// overwriting was not requested.
	ErrOutputExists = errors.New("output file already exists")
)

// DefaultClaimGenerator is the claim_generator_info name written when the
// configuration names none.
const DefaultClaimGenerator = "c2pa-mcp"

// SignerConfig is what LoadSigner needs. Key material arrives as PEM bytes —
// the CLI and the MCP server both read them from files named on the command
// line — and is never echoed in an error or a result.
type SignerConfig struct {
	// KeyPEM holds the private key: an unencrypted PKCS#8 "PRIVATE KEY", a
	// SEC 1 "EC PRIVATE KEY" or a PKCS#1 "RSA PRIVATE KEY" block. Other blocks
	// in the same file (the certificate, say) are skipped.
	KeyPEM []byte
	// CertPEM holds the certificate chain, leaf first, then intermediates. The
	// root may be omitted. Non-certificate blocks are skipped, so the key and
	// certificate may come from one combined file.
	CertPEM []byte
	// ClaimGenerator and ClaimGeneratorVersion name the producing software in
	// the manifest (claim_generator_info). Empty → DefaultClaimGenerator.
	ClaimGenerator        string
	ClaimGeneratorVersion string
	// TimestampAuthority, when set, is an RFC 3161 TSA URL: every signature is
	// timestamped after signing and the token embedded. Empty → no network.
	TimestampAuthority string
	// HTTPClient is used for the TSA request; nil → the library's default.
	HTTPClient *http.Client
}

// Signer is a loaded signing identity shared by the CLI and the MCP server.
type Signer struct {
	signer *c2pa.Signer
	pool   *x509.CertPool // anchored at the chain's top certificate
	name   string         // the leaf's subject, for reports
	tsa    string
}

// LoadSigner parses the PEM material and builds the library signer, which
// checks the key against the leaf, the chain's links and validity, and the
// C2PA certificate profile — so a Signer that loads can only fail on an asset.
func LoadSigner(cfg SignerConfig) (*Signer, error) {
	key, err := parsePrivateKey(cfg.KeyPEM)
	if err != nil {
		return nil, err
	}
	chain, err := parseCertChain(cfg.CertPEM)
	if err != nil {
		return nil, err
	}
	name := cfg.ClaimGenerator
	if name == "" {
		name = DefaultClaimGenerator
	}
	opts := []c2pa.SignerOption{c2pa.WithClaimGenerator(name, cfg.ClaimGeneratorVersion)}
	if cfg.TimestampAuthority != "" {
		opts = append(opts, c2pa.WithTimestampAuthority(cfg.TimestampAuthority))
		if cfg.HTTPClient != nil {
			opts = append(opts, c2pa.WithTimestampHTTPClient(cfg.HTTPClient))
		}
	}
	s, err := c2pa.NewSigner(key, chain, opts...)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(chain[len(chain)-1])
	return &Signer{signer: s, pool: pool, name: certName(chain[0]), tsa: cfg.TimestampAuthority}, nil
}

// Name is the signing certificate's subject, as a verifier would report it.
func (s *Signer) Name() string { return s.name }

// Timestamped reports whether signatures are sent to a timestamp authority.
func (s *Signer) Timestamped() bool { return s.tsa != "" }

// parsePrivateKey finds the first private-key block in pemBytes. Errors never
// carry key bytes: they name the block type or the parser's own message.
func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, ErrSigningKey
		}
		if strings.Contains(block.Type, "ENCRYPTED") || block.Headers["Proc-Type"] == "4,ENCRYPTED" {
			return nil, fmt.Errorf("%w: the key is encrypted; decrypt it first (openssl pkey -in key.pem -out plain.pem)", ErrSigningKey)
		}
		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s block: %v", ErrSigningKey, block.Type, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%w: %T cannot sign", ErrSigningKey, key)
		}
		return signer, nil
	}
}

// parseCertChain collects every CERTIFICATE block in pemBytes, in order.
func parseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSigningCert, err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, ErrSigningCert
	}
	return chain, nil
}

// SignRequest is what one Sign call says about the asset.
type SignRequest struct {
	// Title is the manifest's dc:title; omitted when empty.
	Title string
	// Action is the manifest's first action: "created" (nothing preceded this
	// asset), "opened" (something did — the asset's own manifest, if it has
	// one, becomes the parentOf ingredient), or "auto"/"" to pick opened when
	// the asset already carries a manifest and created otherwise. The library
	// refuses created on an already-signed asset, since a prior manifest
	// proves something preceded it.
	Action string
	// DigitalSourceType is the IPTC digital source type of a created asset: a
	// full URL, or a bare term such as digitalCapture, trainedAlgorithmicMedia
	// or compositeWithTrainedAlgorithmicMedia, which is completed to the IPTC
	// NewsCodes URL; "empty" is C2PA's own http://c2pa.org/digitalsourcetype/empty.
	DigitalSourceType string
	// SoftBinding names a soft binding to compute and write ALONGSIDE the hard
	// binding, which every signed asset still gets: SoftBindingISCC ("iscc",
	// an ISO 24138 Image-Code over a JPEG, PNG or GIF) or SoftBindingNone /
	// "" for none. See softbinding.go for why the choice is this narrow.
	SoftBinding string
}

// SignResult is the JSON-serializable outcome of a Sign call.
type SignResult struct {
	Container string `json:"container"`
	// Action is the first action written: c2pa.created or c2pa.opened.
	Action string `json:"action"`
	// ChainedPriorManifest is true when the asset already carried a manifest,
	// which the new store keeps and names as the parentOf ingredient.
	ChainedPriorManifest bool `json:"chained_prior_manifest"`
	// Timestamped is true when the signature carries an RFC 3161 token.
	Timestamped bool `json:"timestamped"`
	// Size is the signed asset's length in bytes.
	Size int `json:"size"`
	// Output is the path written, when the caller wrote to a file.
	Output string `json:"output,omitempty"`
	// SignedBytes is the signed asset, base64, when the caller asked for it
	// inline instead of a file.
	SignedBytes string `json:"signed_bytes,omitempty"`
	// SoftBinding is the canonical identifier of the soft binding written, when
	// one was asked for — the "ISCC:…" string for SoftBindingISCC. The
	// assertion itself carries that code's raw digest, and Verify.SoftBindings
	// below is what a verifier reads back out of the signed asset.
	SoftBinding string `json:"soft_binding,omitempty"`
	// Verify is the library's verdict on the OUTPUT, anchored at the signing
	// chain's own top certificate and WITHOUT descending into a prior manifest
	// (the c2pa library already refuses to write anything that fails this
	// check, so Valid is confirmation). Run verify on the file for the full
	// picture, including how a prior manifest fares against the trust list.
	Verify VerifyResult `json:"verify"`
}

const iptcDigitalSourceTypePrefix = "http://cv.iptc.org/newscodes/digitalsourcetype/"

// digitalSourceTypeURL completes a bare IPTC term to its NewsCodes URL.
func digitalSourceTypeURL(s string) string {
	switch {
	case s == "":
		return ""
	case s == "empty":
		return c2pa.DigitalSourceTypeEmpty
	case strings.Contains(s, "://"):
		return s
	default:
		return iptcDigitalSourceTypePrefix + s
	}
}

// Sign reads the whole asset from r, embeds a signed manifest, and writes the
// result to w — only on success; on any error nothing reaches w. The asset is
// buffered (the library needs it whole anyway) up to c2pa.ValidateMaxScan.
func (s *Signer) Sign(ctx context.Context, container c2pa.Container, r io.Reader, w io.Writer, req SignRequest) (SignResult, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(c2pa.ValidateMaxScan)+1))
	if err != nil {
		return SignResult{}, fmt.Errorf("read asset: %w", err)
	}
	if len(data) > c2pa.ValidateMaxScan {
		return SignResult{}, c2pa.ErrAssetTooLarge
	}
	// ExtractStore, not Read: Read stops at its 16 MiB triage cap, so a large
	// asset whose store sits past it (a PDF's incremental update, an MP4 with
	// the box after mdat) would look unsigned here and then be refused by the
	// library as already signed. ExtractStore scans as far as Sign itself does.
	store, _ := c2pa.ExtractStore(ctx, container, bytes.NewReader(data))
	present := len(store) > 0

	var action string
	switch req.Action {
	case "", "auto":
		action = c2pa.ActionCreated
		if present {
			action = c2pa.ActionOpened
		}
	case "created", c2pa.ActionCreated:
		action = c2pa.ActionCreated
	case "opened", c2pa.ActionOpened:
		action = c2pa.ActionOpened
	default:
		return SignResult{}, fmt.Errorf("%w: got %q", ErrBadAction, req.Action)
	}

	// Computed from the asset as it arrived, before anything is embedded: a
	// soft binding describes the CONTENT, and the manifest a signer is about to
	// add is not part of it.
	softBinding, softBindingCode, err := softBindingFor(req.SoftBinding, container, data)
	if err != nil {
		return SignResult{}, err
	}

	m := c2pa.Manifest{
		Title: req.Title,
		Actions: []c2pa.Action{{
			Action:            action,
			DigitalSourceType: digitalSourceTypeURL(req.DigitalSourceType),
		}},
	}
	if softBinding != nil {
		m.SoftBindings = []c2pa.SoftBindingInfo{*softBinding}
	}
	var signed bytes.Buffer
	if err := s.signer.Sign(ctx, container, bytes.NewReader(data), &signed, m); err != nil {
		return SignResult{}, err
	}

	res := SignResult{
		Container:            string(container),
		Action:               action,
		ChainedPriorManifest: present && action == c2pa.ActionOpened,
		Timestamped:          s.tsa != "",
		SoftBinding:          softBindingCode,
		Size:                 signed.Len(),
		Verify: verifyWith(ctx, container, bytes.NewReader(signed.Bytes()),
			c2pa.WithSigningTrust(s.pool), c2pa.WithMaxIngredientDepth(0), c2pa.WithOnlineRevocation(false)),
	}
	if _, err := w.Write(signed.Bytes()); err != nil {
		return SignResult{}, fmt.Errorf("write signed asset: %w", err)
	}
	return res, nil
}

// SignToFile signs into path through a temporary file in the same directory,
// renamed into place only once the signed asset is complete — so a failed
// sign never leaves a truncated file behind, and signing a file onto itself
// is safe (the input is read in full first). An existing path is refused
// with ErrOutputExists unless overwrite is set.
func (s *Signer) SignToFile(ctx context.Context, container c2pa.Container, r io.Reader, path string, overwrite bool, req SignRequest) (SignResult, error) {
	if !overwrite {
		if _, err := os.Lstat(path); err == nil {
			return SignResult{}, fmt.Errorf("%w: %s", ErrOutputExists, path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return SignResult{}, fmt.Errorf("stat %q: %w", path, err)
		}
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return SignResult{}, fmt.Errorf("create output: %w", err)
	}
	tmpName := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	res, err := s.Sign(ctx, container, r, tmp, req)
	if err != nil {
		discard()
		return SignResult{}, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return SignResult{}, fmt.Errorf("write output: %w", err)
	}
	// CreateTemp makes a 0600 file; a signed asset is an ordinary file.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		_ = os.Remove(tmpName)
		return SignResult{}, fmt.Errorf("write output: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return SignResult{}, fmt.Errorf("write output: %w", err)
	}
	res.Output = path
	return res, nil
}

// Summary renders a Sign result as a short human-readable block.
func (r SignResult) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SIGNED: %s manifest embedded in the %s asset (%d bytes).\n", r.Action, r.Container, r.Size)
	writeField(&b, "Output", r.Output)
	writeField(&b, "Signed by (verified)", r.Verify.VerifiedSigner)
	writeField(&b, "Active manifest", r.Verify.ActiveManifestLabel)
	writeField(&b, "Prior manifest chained as parentOf", boolStr(r.ChainedPriorManifest))
	writeField(&b, "Timestamped", boolStr(r.Timestamped))
	writeField(&b, "Soft binding written", r.SoftBinding)
	if r.Verify.SignedAt != nil {
		writeField(&b, "Signed at (verified)", r.Verify.SignedAt.Format(timeLayout))
	}
	verdict := "VALID"
	if !r.Verify.Valid {
		verdict = "INVALID"
	}
	writeField(&b, "Output verification (anchored at the signing chain)", verdict)
	if !r.Verify.Valid {
		for _, s := range r.Verify.Statuses {
			if s.Severity == "failure" {
				fmt.Fprintf(&b, "  [failure] %s - %s\n", s.Code, s.Explanation)
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
