package escrow

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// restorable matches what a consumer replaces when it restores a text: the marker of a kept
// value, with its handle in group 1, or the continuation marker of a split token.
var restorable = regexp.MustCompile(`\[REDACTED:[a-z_]+ #(k[a-z2-7]{10})\]|` + regexp.QuoteMeta(redact.ContinuationMarker))

// restore is the restore procedure of the escrow spec: each marker whose handle value knows
// becomes its value, and each continuation marker is dropped.
func restore(text string, value func(handle string) (string, bool)) string {
	return restorable.ReplaceAllStringFunc(text, func(m string) string {
		if m == redact.ContinuationMarker {
			return ""
		}
		if v, ok := value(restorable.FindStringSubmatch(m)[1]); ok {
			return v
		}
		return m
	})
}

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
		restored = append(restored, restore(part, value))
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
	if unknown := "[REDACTED:password #kaaaaaaaaaa]"; restore(unknown, value) != unknown {
		t.Error("a marker with an unknown handle was changed")
	}
}

// Whole tokens in adjacent strings are kept apart: each secret gets a handle that holds exactly
// it, and a neighbouring identifier stays visible.
func TestAdjacentTokensKeepTheirOwnHandles(t *testing.T) {
	t.Parallel()
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	random := func(seed, n int) string {
		const alphabet = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
		var b strings.Builder
		for i := range n {
			b.WriteByte(alphabet[(i*seed+3)%len(alphabet)])
		}
		return b.String()
	}
	jwt := func(seed int) string {
		return "ey" + "J" + random(seed, 30) + ".ey" + "J" + random(seed+2, 60) + "." + random(seed+4, 43)
	}
	slack := "xoxe.xo" + "xp-1-" + random(7, 140)
	slackRefresh := "xo" + "xe-1-" + random(11, 140)
	refresh := "GEbRxBN" + random(13, 40)
	bot := "xo" + "xb-" + random(17, 40)
	for _, tc := range []struct {
		name    string
		doc     map[string]any
		secrets map[string]string // member name, or index in "tokens", to its secret
		visible []string
	}{
		{
			name:    "Slack rotation",
			doc:     map[string]any{"token": slack, "refresh_token": slackRefresh},
			secrets: map[string]string{"token": slack, "refresh_token": slackRefresh},
		},
		{
			name:    "JWT and a refresh token",
			doc:     map[string]any{"access_token": jwt(5), "refresh_token": refresh},
			secrets: map[string]string{"access_token": jwt(5), "refresh_token": refresh},
		},
		{
			name:    "two JWTs",
			doc:     map[string]any{"access_token": jwt(5), "id_token": jwt(19)},
			secrets: map[string]string{"access_token": jwt(5), "id_token": jwt(19)},
		},
		{
			name:    "JWTs in a list",
			doc:     map[string]any{"tokens": []string{jwt(5), jwt(19)}},
			secrets: map[string]string{"0": jwt(5), "1": jwt(19)},
		},
		{
			name:    "token and a request id",
			doc:     map[string]any{"token": bot, "x_request_id": "aB3dE5fG7hJ9"},
			secrets: map[string]string{"token": bot},
			visible: []string{"aB3dE5fG7hJ9"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(tc.doc)
			if err != nil {
				t.Fatal(err)
			}
			e := New(Options{KeyHash: testHash()})
			out, err := engine.RedactJSON(raw, e.Replacer(Source{Server: "s"}))
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			text := func(key string) string {
				v := got[key]
				if list, ok := got["tokens"].([]any); ok {
					v = list[map[string]int{"0": 0, "1": 1}[key]]
				}
				str, ok := v.(string)
				if !ok {
					t.Fatalf("%s is %T, want a string", key, v)
				}
				return str
			}
			for key, secret := range tc.secrets {
				field := text(key)
				m := markerRE.FindStringSubmatch(field)
				if m == nil {
					t.Fatalf("%s = %q, want a marker with a handle", key, field)
				}
				ent, ok := e.store.get(m[2])
				if !ok || string(ent.value) != secret {
					t.Errorf("%s: handle holds %q, want %q", key, ent.value, secret)
				}
			}
			for _, v := range tc.visible {
				if !strings.Contains(string(out), v) {
					t.Errorf("%q was hidden: %s", v, out)
				}
			}
		})
	}
}
