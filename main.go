// Command c2pa-mcp is both a CLI and an MCP server for reading, validating and
// signing C2PA / Content Credentials provenance in JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF files. It wraps the
// github.com/richardwooding/c2pa library.
//
//   - detect: report what a file CLAIMS (fast, unverified — like EXIF)
//   - verify: fully validate signatures, certificate chain, hashes, timestamp
//   - sign:   embed a signed manifest with your own key and certificate chain
//   - serve:  run the MCP server over stdio or Streamable HTTP (with the sign
//     tool when started with a signing identity)
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
	Sign    SignCmd          `cmd:"" help:"Embed a signed C2PA manifest into a file with your own key and certificate chain."`
	Serve   ServeCmd         `cmd:"" help:"Run the MCP server over stdio or Streamable HTTP."`
	Version kong.VersionFlag `help:"Print the version and exit."`
}

// DetectCmd implements `c2pa-mcp detect`.
type DetectCmd struct {
	File string `arg:"" default:"-" help:"Asset file (JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF), or '-' for stdin."`
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
	File             string `arg:"" default:"-" help:"Asset file (JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF), or '-' for stdin."`
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

// SignerFlags name a signing identity. They are shared by sign (where they are
// required) and serve (where they are optional and enable the sign tool). The
// files are read here and handed to analyze as PEM bytes; nothing in this
// process ever prints them.
type SignerFlags struct {
	SigningKey         string `name:"signing-key" env:"C2PA_SIGNING_KEY" help:"PEM file holding the unencrypted private key (PKCS#8, EC or RSA)." type:"existingfile"`
	SigningCert        string `name:"signing-cert" env:"C2PA_SIGNING_CERT" help:"PEM file holding the certificate chain, leaf first (the key file, if it also holds the certificates)." type:"existingfile"`
	TimestampAuthority string `name:"tsa" env:"C2PA_TSA_URL" help:"RFC 3161 timestamp authority URL; every signature is timestamped when set."`
	ClaimGenerator     string `name:"claim-generator" default:"c2pa-mcp" help:"Producer name recorded in the manifest's claim_generator_info."`
}

// configured reports whether either credential flag was given.
func (f SignerFlags) configured() bool { return f.SigningKey != "" || f.SigningCert != "" }

// load reads the PEM files and builds the shared signer.
func (f SignerFlags) load() (*analyze.Signer, error) {
	if f.SigningKey == "" || f.SigningCert == "" {
		return nil, errors.New("both --signing-key and --signing-cert are required to sign")
	}
	keyPEM, err := os.ReadFile(f.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	certPEM, err := os.ReadFile(f.SigningCert)
	if err != nil {
		return nil, fmt.Errorf("read signing certificate: %w", err)
	}
	return analyze.LoadSigner(analyze.SignerConfig{
		KeyPEM:                keyPEM,
		CertPEM:               certPEM,
		ClaimGenerator:        f.ClaimGenerator,
		ClaimGeneratorVersion: version,
		TimestampAuthority:    f.TimestampAuthority,
	})
}

// SignCmd implements `c2pa-mcp sign`.
type SignCmd struct {
	Input             string      `arg:"" help:"Asset to sign (JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF), or '-' for stdin."`
	Output            string      `arg:"" help:"Where to write the signed asset, or '-' for stdout (the summary then goes to stderr)."`
	Signer            SignerFlags `embed:""`
	Title             string      `help:"dc:title recorded in the manifest."`
	Action            string      `enum:"auto,created,opened" default:"auto" help:"First action: created (nothing preceded this asset), opened (something did), or auto — opened when the asset already carries a manifest, created otherwise."`
	DigitalSourceType string      `name:"digital-source-type" help:"IPTC digital source type of a created asset: a full URL or a bare term such as digitalCapture, trainedAlgorithmicMedia or compositeWithTrainedAlgorithmicMedia; 'empty' is C2PA's own."`
	SoftBinding       string      `name:"soft-binding" enum:"none,iscc" default:"none" help:"Also write a soft binding, a perceptual identifier that survives re-encoding: 'iscc' computes an ISO 24138 Image-Code (io.iscc.v0) over a JPEG, PNG or GIF. The hard binding is still written; verifiers report a soft binding without checking it."`
	Force             bool        `help:"Overwrite an existing output file."`
	JSON              bool        `help:"Emit JSON instead of a human-readable summary."`
}

// Run executes the sign command. Nothing is written unless the signed asset
// validated; a failure leaves an existing output file untouched.
func (c *SignCmd) Run() error {
	ctx := context.Background()
	signer, err := c.Signer.load()
	if err != nil {
		return err
	}
	container, r, closer, err := openCLIInput(ctx, c.Input)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	req := analyze.SignRequest{Title: c.Title, Action: c.Action, DigitalSourceType: c.DigitalSourceType, SoftBinding: c.SoftBinding}
	if c.Output == "-" {
		res, err := signer.Sign(ctx, container, r, os.Stdout, req)
		if err != nil {
			return err
		}
		return emitTo(os.Stderr, res, res.Summary(), c.JSON)
	}
	res, err := signer.SignToFile(ctx, container, r, c.Output, c.Force, req)
	if err != nil {
		if errors.Is(err, analyze.ErrOutputExists) {
			return fmt.Errorf("%w (pass --force to overwrite)", err)
		}
		return err
	}
	return emit(res, res.Summary(), c.JSON)
}

// ServeCmd implements `c2pa-mcp serve`.
type ServeCmd struct {
	Transport string      `enum:"stdio,http" default:"stdio" help:"Transport: stdio or http (Streamable HTTP)."`
	HTTPAddr  string      `default:":8080" help:"Listen address for the http transport."`
	HTTPPath  string      `default:"/mcp" help:"URL path the http transport is mounted at."`
	Signer    SignerFlags `embed:""`
}

// Run starts the MCP server on the chosen transport. With a signing identity
// the server also offers the sign tool — to every client that can reach it.
func (c *ServeCmd) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var opts []mcpserver.Option
	if c.Signer.configured() {
		signer, err := c.Signer.load()
		if err != nil {
			return err
		}
		opts = append(opts, mcpserver.WithSigner(signer))
		fmt.Fprintf(os.Stderr, "c2pa-mcp: sign tool enabled, signing as %q (timestamped: %v)\n", signer.Name(), signer.Timestamped())
	}
	server := mcpserver.New(version, opts...)

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
	return emitTo(os.Stdout, v, summary, asJSON)
}

// emitTo is emit onto a chosen stream — stderr when stdout carries the asset.
func emitTo(w io.Writer, v any, summary string, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	_, err := fmt.Fprintln(w, summary)
	return err
}

func main() {
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.Name("c2pa-mcp"),
		kong.Description("Read, validate and sign C2PA / Content Credentials provenance in JPEG, PNG, WebP, GIF, TIFF, HEIC, AVIF, SVG, MP4, MOV, AVI, WAV, MP3 or PDF files, as a CLI or an MCP server."),
		kong.UsageOnError(),
		kong.Vars{"version": versionString()},
	)
	err := kctx.Run()
	if errors.Is(err, errInvalid) {
		os.Exit(1)
	}
	kctx.FatalIfErrorf(err)
}
