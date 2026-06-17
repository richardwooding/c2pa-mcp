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
		Description: "Report what a JPEG or PNG file CLAIMS about its C2PA / Content Credentials " +
			"provenance (generator, title, AI flag, claimed signer and signing time). Fast and " +
			"UNVERIFIED — like reading EXIF; it does not check signatures. Use verify to validate.",
	}, h.detect)

	mcp.AddTool(server, &mcp.Tool{
		Name: "verify",
		Description: "Fully validate a JPEG or PNG file's C2PA / Content Credentials manifest: COSE " +
			"signature, certificate chain against the trust list, assertion and hard-binding hashes, " +
			"and the RFC 3161 timestamp. Returns an overall valid flag plus per-step status codes.",
	}, h.verify)

	return server
}
