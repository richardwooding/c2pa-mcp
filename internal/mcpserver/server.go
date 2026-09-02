// Package mcpserver builds the c2pa-mcp Model Context Protocol server: a thin
// wrapper that exposes the analyze package's Detect and Verify operations as MCP
// tools. The same server value is served over either the stdio or the
// Streamable HTTP transport by the CLI.
package mcpserver

import (
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverName = "c2pa-mcp"

// New builds an MCP server exposing the detect and verify tools. version is
// reported to clients during initialization.
func New(version string) *mcp.Server {
	h := &handlers{
		httpClient: &http.Client{Timeout: 30 * time.Second},
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
			"the same is true of everything under `detect`.",
	}, h.verify)

	return server
}
