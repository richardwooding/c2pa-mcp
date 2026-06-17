// Command c2pa-mcp is both a CLI and an MCP server for reading and validating
// C2PA / Content Credentials provenance in JPEG and PNG files. It wraps the
// github.com/richardwooding/c2pa library.
//
//   - detect: report what a file CLAIMS (fast, unverified — like EXIF)
//   - verify: fully validate signatures, certificate chain, hashes, timestamp
//   - serve:  run the MCP server over stdio or Streamable HTTP
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/richardwooding/c2pa"

	"github.com/richardwooding/c2pa-mcp/internal/analyze"
	"github.com/richardwooding/c2pa-mcp/internal/mcpserver"
)

// Build metadata, set by GoReleaser via -ldflags "-X main.version=... -X
// main.commit=... -X main.date=...". version is the semantic version reported
// to MCP clients; commit and date enrich the CLI's --version output.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString is the rich --version output; the MCP server is given the bare
// semantic version.
func versionString() string {
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}

// CLI is the Kong command tree.
type CLI struct {
	Detect  DetectCmd        `cmd:"" help:"Report what a file claims about its provenance (fast, UNVERIFIED — like EXIF)."`
	Verify  VerifyCmd        `cmd:"" help:"Fully validate a file's C2PA signatures, certificate chain, hashes, and timestamp."`
	Serve   ServeCmd         `cmd:"" help:"Run the MCP server over stdio or Streamable HTTP."`
	Version kong.VersionFlag `help:"Print the version and exit."`
}

// DetectCmd implements `c2pa-mcp detect`.
type DetectCmd struct {
	File string `arg:"" default:"-" help:"Image file (JPEG or PNG), or '-' for stdin."`
	JSON bool   `help:"Emit JSON instead of a human-readable summary."`
}

// Run executes the detect command.
func (c *DetectCmd) Run() error {
	ctx := context.Background()
	container, r, closer, err := openCLIInput(ctx, c.File)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	res := analyze.Detect(ctx, container, r)
	return emit(res, res.Summary(), c.JSON)
}

// VerifyCmd implements `c2pa-mcp verify`.
type VerifyCmd struct {
	File             string `arg:"" default:"-" help:"Image file (JPEG or PNG), or '-' for stdin."`
	JSON             bool   `help:"Emit JSON instead of a human-readable summary."`
	SigningTrust     string `help:"Path to a PEM bundle overriding the embedded signing-anchor trust list." type:"existingfile"`
	TimestampTrust   string `help:"Path to a PEM bundle overriding the embedded timestamp-authority trust list." type:"existingfile"`
	OnlineRevocation bool   `help:"Enable OCSP/CRL revocation checks over the network (soft-fail)."`
	MaxScan          int    `help:"Override the maximum number of leading bytes to read (0 = library default)."`
}

// Run executes the verify command. It exits non-zero when the manifest is invalid.
func (c *VerifyCmd) Run() error {
	ctx := context.Background()

	opts := analyze.VerifyOptions{
		OnlineRevocation: c.OnlineRevocation,
		MaxScan:          c.MaxScan,
	}
	var err error
	if c.SigningTrust != "" {
		if opts.SigningTrustPEM, err = os.ReadFile(c.SigningTrust); err != nil {
			return fmt.Errorf("read signing trust: %w", err)
		}
	}
	if c.TimestampTrust != "" {
		if opts.TimestampTrustPEM, err = os.ReadFile(c.TimestampTrust); err != nil {
			return fmt.Errorf("read timestamp trust: %w", err)
		}
	}

	container, r, closer, err := openCLIInput(ctx, c.File)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	res, err := analyze.Verify(ctx, container, r, opts)
	if err != nil {
		return err
	}
	if err := emit(res, res.Summary(), c.JSON); err != nil {
		return err
	}
	if !res.Valid {
		// Signal invalidity to scripts without printing a redundant error.
		return errInvalid
	}
	return nil
}

// errInvalid is returned by verify to force a non-zero exit on an invalid
// manifest. main maps it to exit code 1 without printing it.
var errInvalid = errors.New("manifest is not valid")

// ServeCmd implements `c2pa-mcp serve`.
type ServeCmd struct {
	Transport string `enum:"stdio,http" default:"stdio" help:"Transport: stdio or http (Streamable HTTP)."`
	HTTPAddr  string `default:":8080" help:"Listen address for the http transport."`
	HTTPPath  string `default:"/mcp" help:"URL path the http transport is mounted at."`
}

// Run starts the MCP server on the chosen transport.
func (c *ServeCmd) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := mcpserver.New(version)

	switch c.Transport {
	case "stdio":
		return server.Run(ctx, &mcp.StdioTransport{})

	case "http":
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		mux := http.NewServeMux()
		mux.Handle(c.HTTPPath, handler)
		httpServer := &http.Server{
			Addr:              c.HTTPAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		errCh := make(chan error, 1)
		go func() {
			fmt.Fprintf(os.Stderr, "c2pa-mcp serving Streamable HTTP on %s%s\n", c.HTTPAddr, c.HTTPPath)
			errCh <- httpServer.ListenAndServe()
		}()

		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpServer.Shutdown(shutdownCtx)
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}

	default:
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
}

// openCLIInput resolves a CLI file argument ("-" means stdin) to a sniffed reader.
func openCLIInput(ctx context.Context, file string) (container c2pa.Container, r io.Reader, closer func() error, err error) {
	in := analyze.Input{}
	if file == "-" || file == "" {
		in.Stdin = os.Stdin
	} else {
		in.Path = file
	}
	return analyze.Open(ctx, in, nil)
}

// emit prints either the JSON encoding of v or the precomputed text summary.
func emit(v any, summary string, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	fmt.Println(summary)
	return nil
}

func main() {
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.Name("c2pa-mcp"),
		kong.Description("Read and validate C2PA / Content Credentials provenance in JPEG and PNG files, as a CLI or an MCP server."),
		kong.UsageOnError(),
		kong.Vars{"version": versionString()},
	)
	err := kctx.Run()
	if errors.Is(err, errInvalid) {
		os.Exit(1)
	}
	kctx.FatalIfErrorf(err)
}
