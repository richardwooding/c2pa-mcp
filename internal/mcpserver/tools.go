package mcpserver

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/richardwooding/c2pa-mcp/internal/analyze"
)

// DetectArgs are the inputs to the detect tool. Exactly one of Path, URL, or
// Bytes must be set.
type DetectArgs struct {
	Path  string `json:"path,omitempty" jsonschema:"Local filesystem path to a JPEG or PNG image"`
	URL   string `json:"url,omitempty" jsonschema:"HTTP(S) URL of a JPEG or PNG image to fetch and analyze"`
	Bytes string `json:"bytes,omitempty" jsonschema:"Base64-encoded (standard encoding) JPEG or PNG image bytes"`
}

// VerifyArgs are the inputs to the verify tool. Exactly one of Path, URL, or
// Bytes must be set.
type VerifyArgs struct {
	Path             string `json:"path,omitempty" jsonschema:"Local filesystem path to a JPEG or PNG image"`
	URL              string `json:"url,omitempty" jsonschema:"HTTP(S) URL of a JPEG or PNG image to fetch and analyze"`
	Bytes            string `json:"bytes,omitempty" jsonschema:"Base64-encoded (standard encoding) JPEG or PNG image bytes"`
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

// handlers carries the shared dependencies tool handlers need.
type handlers struct {
	httpClient *http.Client
}
