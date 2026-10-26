package escrow

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// A token split across two JSON strings is kept whole under the first part's handle: restoring
// puts it back where it started and drops the continuation marker, so the restored parts join
// to the original text.
func TestRestoreSplitToken(t *testing.T) {
	t.Parallel()
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	token := "gh" + "p_" + strings.Repeat("a1B2c3D4e5F6", 3)
	parts := []string{"use " + token[:12], token[12:] + " now", "password: Qwerty-12345"}
	doc, err := json.Marshal(map[string]any{"parts": parts})
	if err != nil {
		t.Fatal(err)
	}
	e := New(Options{KeyHash: testHash()})
	out, err := engine.RedactJSON(doc, e.Replacer(Source{Server: "chat"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), token[:12]) || strings.Contains(string(out), token[12:]) {
		t.Fatalf("a part of the token survived: %s", out)
	}
	var got struct{ Parts []string }
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Parts[1], redact.ContinuationMarker) {
		t.Fatalf("second part = %q, want the continuation marker", got.Parts[1])
	}
	value := func(handle string) (string, bool) {
		ent, ok := e.store.get(handle)
		return string(ent.value), ok
	}
	var restored []string
	for _, part := range got.Parts {
		restored = append(restored, Restore(part, value))
	}
	want := []string{"use " + token, " now", parts[2]}
	for i := range want {
		if restored[i] != want[i] {
			t.Errorf("part %d restored to %q, want %q", i, restored[i], want[i])
		}
	}
	if strings.Join(restored, "") != strings.Join(parts, "") {
		t.Error("the restored parts do not join to the original")
	}
	if unknown := "[REDACTED:password #kaaaaaaaaaa]"; Restore(unknown, value) != unknown {
		t.Error("a marker with an unknown handle was changed")
	}
}
