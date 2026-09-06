package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/richardwooding/c2pa-mcp/internal/analyze"
)

// DetectArgs are the inputs to the detect tool. Exactly one of Path, URL, or
// Bytes must be set.
type DetectArgs struct {
	Path  string `json:"path,omitempty" jsonschema:"Local filesystem path to a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file"`
	URL   string `json:"url,omitempty" jsonschema:"HTTP(S) URL of a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file to fetch and analyze"`
	Bytes string `json:"bytes,omitempty" jsonschema:"Base64-encoded (standard encoding) JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF bytes"`
}

// VerifyArgs are the inputs to the verify tool. Exactly one of Path, URL, or
// Bytes must be set.
type VerifyArgs struct {
	Path             string `json:"path,omitempty" jsonschema:"Local filesystem path to a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file"`
	URL              string `json:"url,omitempty" jsonschema:"HTTP(S) URL of a JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF file to fetch and analyze"`
	Bytes            string `json:"bytes,omitempty" jsonschema:"Base64-encoded (standard encoding) JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF bytes"`
	OnlineRevocation bool   `json:"online_revocation,omitempty" jsonschema:"Enable OCSP/CRL revocation checks over the network (soft-fail)"`
	MaxScan          int    `json:"max_scan,omitempty" jsonschema:"Override the maximum number of leading bytes to read (0 = library default of 256 MiB)"`
}

func (h *handlers) detect(ctx context.Context, _ *mcp.CallToolRequest, args DetectArgs) (*mcp.CallToolResult, analyze.DetectResult, error) {
	container, r, closer, err := analyze.Open(ctx, analyze.Input{Path: args.Path, URL: args.URL, Base64: args.Bytes}, h.httpClient)
	if err != nil {
		return nil, analyze.DetectResult{}, err
	}
	defer func() { _ = closer() }()

	res := analyze.Detect(ctx, container, r)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: res.Summary()}},
	}, res, nil
}

func (h *handlers) verify(ctx context.Context, _ *mcp.CallToolRequest, args VerifyArgs) (*mcp.CallToolResult, analyze.VerifyResult, error) {
	container, r, closer, err := analyze.Open(ctx, analyze.Input{Path: args.Path, URL: args.URL, Base64: args.Bytes}, h.httpClient)
	if err != nil {
		return nil, analyze.VerifyResult{}, err
	}
	defer func() { _ = closer() }()

	res, err := analyze.Verify(ctx, container, r, analyze.VerifyOptions{
		OnlineRevocation: args.OnlineRevocation,
		MaxScan:          args.MaxScan,
	})
	if err != nil {
		return nil, analyze.VerifyResult{}, err
	}
	// An invalid manifest is a normal result, not a tool error.
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: res.Summary()}},
	}, res, nil
}

// SignArgs are the inputs to the sign tool. Exactly one of Path, URL, or Bytes
// must be set; Output is required unless the asset arrived as Bytes.
type SignArgs struct {
	Path              string `json:"path,omitempty" jsonschema:"Local filesystem path of the asset to sign"`
	URL               string `json:"url,omitempty" jsonschema:"HTTP(S) URL of the asset to fetch and sign"`
	Bytes             string `json:"bytes,omitempty" jsonschema:"Base64-encoded (standard encoding) asset bytes to sign"`
	Output            string `json:"output,omitempty" jsonschema:"Local filesystem path to write the signed asset to. Required for path and url inputs. When omitted for a bytes input, the signed asset is returned base64-encoded as signed_bytes"`
	Overwrite         bool   `json:"overwrite,omitempty" jsonschema:"Replace an existing output file (default: refuse)"`
	Title             string `json:"title,omitempty" jsonschema:"dc:title recorded in the manifest"`
	Action            string `json:"action,omitempty" jsonschema:"First action: created (nothing preceded this asset) or opened (something did). Default: opened when the asset already carries a manifest, created otherwise"`
	DigitalSourceType string `json:"digital_source_type,omitempty" jsonschema:"IPTC digital source type of a created asset: a full URL or a bare term such as digitalCapture, trainedAlgorithmicMedia or compositeWithTrainedAlgorithmicMedia; 'empty' is C2PA's own"`
}

// errOutputRequired is the sign tool's refusal to guess where a file should go.
var errOutputRequired = errors.New("output is required for path and url inputs (pass the asset as bytes to receive signed_bytes instead)")

func (h *handlers) sign(ctx context.Context, _ *mcp.CallToolRequest, args SignArgs) (*mcp.CallToolResult, analyze.SignResult, error) {
	if args.Output == "" && args.Bytes == "" {
		return nil, analyze.SignResult{}, errOutputRequired
	}
	container, r, closer, err := analyze.Open(ctx, analyze.Input{Path: args.Path, URL: args.URL, Base64: args.Bytes}, h.httpClient)
	if err != nil {
		return nil, analyze.SignResult{}, err
	}
	defer func() { _ = closer() }()

	req := analyze.SignRequest{Title: args.Title, Action: args.Action, DigitalSourceType: args.DigitalSourceType}
	var res analyze.SignResult
	if args.Output != "" {
		res, err = h.signer.SignToFile(ctx, container, r, args.Output, args.Overwrite, req)
	} else {
		var signed bytes.Buffer
		res, err = h.signer.Sign(ctx, container, r, &signed, req)
		res.SignedBytes = base64.StdEncoding.EncodeToString(signed.Bytes())
	}
	if err != nil {
		return nil, analyze.SignResult{}, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: res.Summary()}},
	}, res, nil
}

// handlers carries the shared dependencies tool handlers need.
type handlers struct {
	httpClient *http.Client
	signer     *analyze.Signer // nil: the sign tool is not registered
}
