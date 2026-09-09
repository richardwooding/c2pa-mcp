// Package mcpserver builds the c2pa-mcp Model Context Protocol server: a thin
// wrapper that exposes the analyze package's Detect, Verify and — when the
// server was started with a signing identity — Sign operations as MCP tools.
// The same server value is served over either the stdio or the Streamable HTTP
// transport by the CLI.
package mcpserver

import (
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/richardwooding/c2pa-mcp/internal/analyze"
)

const serverName = "c2pa-mcp"

// Option configures New.
type Option func(*handlers)

// WithSigner gives the server a signing identity and registers the sign tool.
// Without it the tool is not advertised at all: a client should not see a
// capability the server cannot honour, and key material is the operator's to
// configure at startup, never a tool argument.
func WithSigner(s *analyze.Signer) Option {
	return func(h *handlers) { h.signer = s }
}

// New builds an MCP server exposing the detect and verify tools, plus sign when
// WithSigner is given. version is reported to clients during initialization.
func New(version string, opts ...Option) *mcp.Server {
	h := &handlers{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(h)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version,
		Title:   "C2PA / Content Credentials reader & validator",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "detect",
		Description: "Report what a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file CLAIMS about its C2PA / Content Credentials " +
			"provenance (generator, title, AI flag, claimed signer and signing time). Fast and " +
			"UNVERIFIED — like reading EXIF; it does not check signatures. Use verify to validate.",
	}, h.detect)

	mcp.AddTool(server, &mcp.Tool{
		Name: "verify",
		Description: "Fully validate a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file's C2PA / Content Credentials manifest: COSE " +
			"signature, certificate chain against the trust list, assertion and hard-binding hashes, " +
			"and the RFC 3161 timestamp. Returns an overall valid flag plus per-step status codes. " +
			"Read `verified_signer` for who provably signed it — it is empty unless the signature " +
			"verified AND the chain reached a trust anchor. `signers` is the chain as PRESENTED in " +
			"the file and is populated even when validation failed, so it is a claim, not proof; " +
			"the same is true of everything under `detect`. `binding` answers the separate question " +
			"of whether THESE bytes are the ones that were signed: verified, failed, none (nothing " +
			"bound the asset), or unevaluated — which is neither a pass nor a failure but \"a hard " +
			"binding exists and this call did not check it\", as for a PDF manifest attached to an " +
			"embedded object, an asset past the scan cap, or a fragmented asset without its " +
			"fragments. A manifest can be valid with an unevaluated binding. `soft_bindings` lists " +
			"any perceptual identifiers the manifest carries (a watermark or a fingerprint, such as " +
			"an ISCC) — REPORTED, never checked: matching one means recomputing it and comparing " +
			"within a tolerance, which is a policy decision, so nothing here says the content " +
			"matches. Do not report a soft binding as evidence of anything. `identities` lists any " +
			"CAWG identity assertions — named actors who signed over the content with their own " +
			"credential. Read each entry's `name` for who was PROVEN (empty unless `trusted`) and " +
			"`presented_as` for who was merely claimed — the same split as `verified_signer` and " +
			"`signers`. An identity means the actor VOUCHED for those assertions: it conveys neither " +
			"attribution nor ownership, so never say an asset was created by them. For an aggregation " +
			"credential, `verified_identities` is the AGGREGATOR'S word about signals it checked, " +
			"proven only as far as that aggregator is trusted. Neither trust list has a default, so " +
			"unproven is the normal, honest outcome rather than a warning; a " +
			"cawg.ica.did_unsupported_method failure means this build cannot resolve that " +
			"aggregator's DID method, which is a limit here and not a defect in the file.",
	}, h.verify)

	if h.signer != nil {
		mcp.AddTool(server, &mcp.Tool{
			Name: "sign",
			Description: "Sign a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file with THIS " +
				"SERVER'S configured signing key: embeds a C2PA claim.v2 manifest (title, a created or " +
				"opened action, the content hash) and writes a signed copy. An asset that already carries " +
				"Content Credentials keeps them — the prior manifest becomes the new one's parentOf " +
				"ingredient — which requires `action` opened (the default when a manifest is present); " +
				"created on such an asset is refused. Input: exactly one of path, url or bytes. Output: " +
				"`output` names the file to write (required for path and url inputs; an existing file is " +
				"refused unless `overwrite` is true); a bytes input may omit it to receive the signed asset " +
				"as `signed_bytes`. The result's `verify` block is the c2pa library's verdict on the output, " +
				"including the `binding` the manifest just written covers, " +
				"anchored at the signing certificate chain and without re-validating a prior manifest — call " +
				"verify on the output for the full picture. Optional `soft_binding: \"iscc\"` ALSO writes a " +
				"soft binding: an ISO 24138 ISCC Image-Code (io.iscc.v0) computed from the image content, " +
				"which survives the re-encoding and metadata stripping that break the hard binding, so a " +
				"copy can be matched back to this manifest through a provenance store. Still images this " +
				"build can decode only — JPEG, PNG, GIF, WebP and TIFF — and the hard binding is still " +
				"written, since a soft binding is never an asset's only content binding. Anyone who can call this tool signs with the " +
				"content binding. When the server was started with an identity credential, `identity_roles` " +
				"and `identity_references` also write a cawg.identity assertion: a second signature by a " +
				"NAMED ACTOR saying who vouches for the content. That actor's key, like the signing key, " +
				"is the operator's and is never a tool argument. Anyone who can call this tool signs " +
				"with the operator's key.",
		}, h.sign)
	}

	return server
}
