package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/richardwooding/c2pa-mcp/internal/analyze"
	"github.com/richardwooding/c2pa-mcp/internal/testpki"
)

const fixture = "../../testdata/c2pa_signed.jpg"

// connect wires an in-memory client to a freshly built server and returns the
// client session. The server is connected before the client, as the SDK requires.
func connect(t *testing.T, opts ...Option) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := New("test", opts...)
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func fixtureBase64(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// structuredInto re-marshals the result's StructuredContent into out.
func structuredInto(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatal("StructuredContent is nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal structured content: %v", err)
	}
}

func firstText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("no content in result")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("first content is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func TestListTools(t *testing.T) {
	session := connect(t)
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{"detect", "verify"} {
		if !got[want] {
			t.Errorf("tool %q not advertised", want)
		}
	}
	if got["sign"] {
		t.Error("sign advertised without a signing identity")
	}
}

func TestDetectTool(t *testing.T) {
	session := connect(t)
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "detect",
		Arguments: map[string]any{"bytes": fixtureBase64(t)},
	})
	if err != nil {
		t.Fatalf("call detect: %v", err)
	}
	if res.IsError {
		t.Fatalf("detect reported tool error: %s", firstText(t, res))
	}
	if !strings.Contains(firstText(t, res), "C2PA manifest present") {
		t.Fatalf("unexpected text summary: %q", firstText(t, res))
	}

	var got analyze.DetectResult
	structuredInto(t, res, &got)
	if !got.Present {
		t.Fatal("structured Present = false")
	}
	if got.SignedBy != "C2PA Signer" {
		t.Fatalf("SignedBy = %q, want %q", got.SignedBy, "C2PA Signer")
	}
}

func TestVerifyTool(t *testing.T) {
	session := connect(t)
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "verify",
		Arguments: map[string]any{"bytes": fixtureBase64(t)},
	})
	if err != nil {
		t.Fatalf("call verify: %v", err)
	}
	// An invalid manifest is a normal result, not a tool error.
	if res.IsError {
		t.Fatalf("verify reported tool error: %s", firstText(t, res))
	}

	var got analyze.VerifyResult
	structuredInto(t, res, &got)
	if got.Valid {
		t.Fatal("Valid = true, want false (untrusted test PKI)")
	}
	if len(got.Statuses) == 0 {
		t.Fatal("no statuses returned")
	}
}

func TestDetectTool_BadInput(t *testing.T) {
	session := connect(t)
	// No source provided -> handler returns an error -> surfaced as a tool error.
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "detect",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call detect: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError for missing input source")
	}
}

func testSigner(t *testing.T) *analyze.Signer {
	t.Helper()
	creds, err := testpki.SelfSigned("MCP Test Signer")
	if err != nil {
		t.Fatal(err)
	}
	s, err := analyze.LoadSigner(analyze.SignerConfig{KeyPEM: creds.KeyPEM(), CertPEM: creds.CertPEM()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func toolNames(t *testing.T, session *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	return got
}

func TestSignTool_AbsentWithoutSigner(t *testing.T) {
	if toolNames(t, connect(t))["sign"] {
		t.Fatal("sign tool advertised without a signing identity")
	}
}

func TestSignTool_Bytes(t *testing.T) {
	session := connect(t, WithSigner(testSigner(t)))
	if !toolNames(t, session)["sign"] {
		t.Fatal("sign tool not advertised with a signing identity")
	}
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"bytes": fixtureBase64(t), "title": "signed by mcp"},
	})
	if err != nil {
		t.Fatalf("call sign: %v", err)
	}
	if res.IsError {
		t.Fatalf("sign reported tool error: %s", firstText(t, res))
	}
	if !strings.Contains(firstText(t, res), "SIGNED: c2pa.opened") {
		t.Fatalf("unexpected summary: %q", firstText(t, res))
	}
	var got analyze.SignResult
	structuredInto(t, res, &got)
	if got.Action != "c2pa.opened" || !got.ChainedPriorManifest || !got.Verify.Valid || got.Output != "" {
		t.Fatalf("result = %+v", got)
	}
	signed, err := base64.StdEncoding.DecodeString(got.SignedBytes)
	if err != nil || len(signed) != got.Size {
		t.Fatalf("signed_bytes: %v, %d bytes want %d", err, len(signed), got.Size)
	}

	// The signed asset reads back through the detect tool as claimed.
	det, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "detect",
		Arguments: map[string]any{"bytes": got.SignedBytes},
	})
	if err != nil || det.IsError {
		t.Fatalf("detect on signed output: %v %v", err, det)
	}
	var d analyze.DetectResult
	structuredInto(t, det, &d)
	if d.Title != "signed by mcp" || d.SignedBy != "MCP Test Signer" {
		t.Fatalf("detect = %+v", d)
	}
}

// TestSignTool_SoftBindingISCC drives the soft binding through the MCP surface,
// then reads it back with the verify tool — the two halves an agent uses.
func TestSignTool_SoftBindingISCC(t *testing.T) {
	session := connect(t, WithSigner(testSigner(t)))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"bytes": fixtureBase64(t), "soft_binding": "iscc"},
	})
	if err != nil {
		t.Fatalf("call sign: %v", err)
	}
	if res.IsError {
		t.Fatalf("sign reported tool error: %s", firstText(t, res))
	}
	if !strings.Contains(firstText(t, res), "Soft binding written: ISCC:") {
		t.Fatalf("the summary should name the code written: %q", firstText(t, res))
	}
	var got analyze.SignResult
	structuredInto(t, res, &got)
	if !strings.HasPrefix(got.SoftBinding, "ISCC:") {
		t.Fatalf("soft_binding = %q, want an ISCC: string", got.SoftBinding)
	}
	if len(got.Verify.SoftBindings) != 1 || got.Verify.SoftBindings[0].Algorithm != "io.iscc.v0" {
		t.Fatalf("verify block reported %+v", got.Verify.SoftBindings)
	}

	ver, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "verify",
		Arguments: map[string]any{"bytes": got.SignedBytes},
	})
	if err != nil || ver.IsError {
		t.Fatalf("verify on signed output: %v %v", err, ver)
	}
	var v analyze.VerifyResult
	structuredInto(t, ver, &v)
	if len(v.SoftBindings) != 1 {
		t.Fatalf("verify reported %d soft bindings, want 1", len(v.SoftBindings))
	}
	sb := v.SoftBindings[0]
	if sb.Name != got.SoftBinding || !sb.WellFormed || !sb.AlgorithmRegistered || sb.AlgorithmType != "fingerprint" {
		t.Fatalf("verify reported %+v, want the ISCC %q as a registered fingerprint", sb, got.SoftBinding)
	}
}

// TestSignTool_SoftBindingRefused: an algorithm this build cannot compute is a
// tool error, not a quiet sign without one.
func TestSignTool_SoftBindingRefused(t *testing.T) {
	session := connect(t, WithSigner(testSigner(t)))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"bytes": fixtureBase64(t), "soft_binding": "com.digimarc.v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(firstText(t, res), "soft binding must be") {
		t.Fatalf("expected a refusal, got %v %q", res.IsError, firstText(t, res))
	}
}

func TestSignTool_PathOutput(t *testing.T) {
	session := connect(t, WithSigner(testSigner(t)))
	dir := t.TempDir()
	out := filepath.Join(dir, "signed.jpg")

	// path input without output is refused before anything is read.
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"path": fixture},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(firstText(t, res), "output is required") {
		t.Fatalf("expected the output-required error, got %v %q", res.IsError, firstText(t, res))
	}

	res, err = session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"path": fixture, "output": out, "action": "opened"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("sign reported tool error: %s", firstText(t, res))
	}
	var got analyze.SignResult
	structuredInto(t, res, &got)
	if got.Output != out || got.SignedBytes != "" {
		t.Fatalf("result = %+v", got)
	}
	info, err := os.Stat(out)
	if err != nil || int(info.Size()) != got.Size {
		t.Fatalf("output file: %v", err)
	}

	// A second call refuses to overwrite unless asked.
	res, err = session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"path": fixture, "output": out},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(firstText(t, res), "already exists") {
		t.Fatalf("expected an overwrite refusal, got %v %q", res.IsError, firstText(t, res))
	}
	res, err = session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"path": fixture, "output": out, "overwrite": true},
	})
	if err != nil || res.IsError {
		t.Fatalf("overwrite: %v %v", err, res)
	}
}

func TestSignTool_CreatedOnSignedRefused(t *testing.T) {
	session := connect(t, WithSigner(testSigner(t)))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sign",
		Arguments: map[string]any{"bytes": fixtureBase64(t), "action": "created"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("created on an already-signed asset should be a tool error")
	}
}
