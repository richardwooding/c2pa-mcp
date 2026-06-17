package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/richardwooding/c2pa-mcp/internal/analyze"
)

const fixture = "../../testdata/c2pa_signed.jpg"

// connect wires an in-memory client to a freshly built server and returns the
// client session. The server is connected before the client, as the SDK requires.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := New("test")
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
