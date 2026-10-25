package mcpredact

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// FuzzCallToolResult decodes arbitrary bytes as an MCP client would and checks that every
// result the SDK accepts redacts without error and re-encodes.
func FuzzCallToolResult(f *testing.F) {
	for _, seed := range []string{
		`{"content":[]}`,
		`{"content":[{"type":"text","text":"password: hunter22"}]}`,
		`{"content":[{"type":"text","text":"{\"token\":\"abc-123-def\"}","_meta":{"k":"v"}}],"structuredContent":{"pin":123456}}`,
		`{"content":[{"type":"resource","resource":{"uri":"x://1","mimeType":"text/plain","blob":"cGFzc3dvcmQ6IGh1bnRlcjIy"}}]}`,
		`{"content":[{"type":"resource_link","uri":"https://u:p4ss-word@example.com/","name":"n","title":"t","description":"token: abc123def"}]}`,
		`{"content":[{"type":"tool_use","id":"1","name":"n","input":{"api_key":"in-put-key-1"}},` +
			`{"type":"tool_result","toolUseId":"1","content":[{"type":"text","text":"` + fake("ghp_", 36) + `"}],"structuredContent":[1,"x"]}]}`,
		`{"content":[{"type":"image","data":"AAAA","mimeType":"image/png"}],"isError":true,"_meta":{"password":"m-pw-1"}}`,
	} {
		f.Add([]byte(seed))
	}
	r := newRedactor(f, 0)
	f.Fuzz(func(t *testing.T, data []byte) {
		var res mcp.CallToolResult
		if json.Unmarshal(data, &res) != nil {
			return
		}
		got, err := r.CallToolResult(&res, redact.Marker)
		if err != nil {
			t.Fatalf("decoded result failed: %v", err)
		}
		if _, err := json.Marshal(got); err != nil {
			t.Fatalf("redacted result does not encode: %v", err)
		}
	})
}
