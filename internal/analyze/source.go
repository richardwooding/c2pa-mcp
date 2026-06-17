// Package analyze is the shared adapter between the github.com/richardwooding/c2pa
// library and the c2pa-mcp CLI and MCP server. It resolves an image from one of
// several sources, sniffs its container format (the c2pa library trusts the
// caller to name the format), and produces JSON-serializable Detect/Verify
// results used identically by both front ends.
package analyze

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/richardwooding/c2pa"
)

// ErrUnsupportedFormat is returned when the input is neither JPEG nor PNG. The
// c2pa library only reads manifests from those two containers.
var ErrUnsupportedFormat = errors.New("unsupported image format: only JPEG and PNG are supported")

// ErrNoSource is returned when an Input names zero sources, and ErrMultipleSources
// when it names more than one. Exactly one must be set.
var (
	ErrNoSource        = errors.New("no input source provided: set exactly one of path, url, or bytes")
	ErrMultipleSources = errors.New("multiple input sources provided: set exactly one of path, url, or bytes")
)

// Input names exactly one image source. Path, URL and Base64 are the
// caller-facing options; Stdin is an internal escape hatch the CLI uses for
// the "-" file argument and is not exposed as an MCP tool argument.
type Input struct {
	// Path is a local filesystem path.
	Path string
	// URL is an HTTP(S) URL the server fetches over the network.
	URL string
	// Base64 is base64-encoded (standard encoding) image bytes.
	Base64 string
	// Stdin, when non-nil, is read directly. Used by the CLI for "-".
	Stdin io.Reader
}

// magic byte signatures the c2pa library understands.
var (
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
	pngMagic  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
)

// Open resolves in to a reader, sniffs its container format, and returns both
// alongside a closer the caller must invoke when done. The returned reader is
// positioned at the start of the asset (sniffing peeks, it does not consume),
// so it can be handed straight to c2pa.Read or c2pa.Validate.
//
// httpClient is used only for URL inputs; pass nil to use http.DefaultClient.
// The stream is not buffered into memory for Path/Stdin inputs, so it stays
// within the c2pa validator's large scan ceiling.
func Open(ctx context.Context, in Input, httpClient *http.Client) (container c2pa.Container, r io.Reader, closer func() error, err error) {
	raw, closer, err := openRaw(ctx, in, httpClient)
	if err != nil {
		return "", nil, nil, err
	}

	br := bufio.NewReader(raw)
	container, err = sniff(br)
	if err != nil {
		_ = closer()
		return "", nil, nil, err
	}
	return container, br, closer, nil
}

// openRaw selects the single configured source and returns an unbuffered reader
// plus a closer. It does not sniff.
func openRaw(ctx context.Context, in Input, httpClient *http.Client) (io.Reader, func() error, error) {
	noop := func() error { return nil }

	n := 0
	if in.Path != "" {
		n++
	}
	if in.URL != "" {
		n++
	}
	if in.Base64 != "" {
		n++
	}
	if in.Stdin != nil {
		n++
	}
	switch {
	case n == 0:
		return nil, nil, ErrNoSource
	case n > 1:
		return nil, nil, ErrMultipleSources
	}

	switch {
	case in.Stdin != nil:
		return in.Stdin, noop, nil

	case in.Path != "":
		f, err := os.Open(in.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("open %q: %w", in.Path, err)
		}
		return f, f.Close, nil

	case in.URL != "":
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.URL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("build request for %q: %w", in.URL, err)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch %q: %w", in.URL, err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, nil, fmt.Errorf("fetch %q: unexpected status %s", in.URL, resp.Status)
		}
		return resp.Body, resp.Body.Close, nil

	default: // in.Base64 != ""
		data, err := base64.StdEncoding.DecodeString(in.Base64)
		if err != nil {
			return nil, nil, fmt.Errorf("decode base64 input: %w", err)
		}
		return bytes.NewReader(data), noop, nil
	}
}

// sniff peeks at the leading bytes of br and maps them to a c2pa.Container.
// Peeking does not advance the reader.
func sniff(br *bufio.Reader) (c2pa.Container, error) {
	head, err := br.Peek(len(pngMagic))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("read image header: %w", err)
	}
	switch {
	case bytes.HasPrefix(head, jpegMagic):
		return c2pa.JPEG, nil
	case bytes.HasPrefix(head, pngMagic):
		return c2pa.PNG, nil
	default:
		return "", ErrUnsupportedFormat
	}
}
