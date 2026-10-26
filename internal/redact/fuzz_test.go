package redact

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzSeeds are inputs that reach every rule, the JSON rewrite and the escaped-break masking.
func fuzzSeeds() []string {
	return []string{
		"",
		"plain text without secrets",
		"password: hunter22 and " + fake("ghp_", 36),
		`ok\npassword: "Xk9\nP2qZ7"\tToken: abc123def`,
		"DB_PASSWORD=hunter2!x\nexport MY_API_KEY=\"abc 123\" # note",
		"postgres://app:s3cr3t-Pa55@db.example.com/app",
		"Authorization: Bearer " + fake("", 30),
		"-----BEGIN " + "PRIVATE KEY-----\n" + fake("", 40),
		"bot 123456789:" + fake("AA", 33),
		"mysql --password hunter-cli-2 db",
		`log {\"password\":\"esc-aped-1\"} {"client_secret": "cs-123456"}`,
		"логин/пароль: admin / Qwerty123, ключ " + fake("AKIA", 16),
		"Пароль:\nNextLine-77 токен — " + fake("", 30),
		"here is " + fake("", 32) + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + fake("", 43),
		`{"token":{"access":"abcdef123","type":"Bearer"},"password":12345678,"x":"{\"pwd\":\"zz9\"}"}`,
		`[{"Authorization":"Basic ` + fake("", 20) + `"},"password: xpy-123"]`,
		"\\\\n\\n\\\x00password\u200b：\u00a0zz",
		"db:\n  password:\r\n    hunter22\n  token:\nuser: x\napi_key =\n'sk12345678';",
	}
}

var fuzzOptions = Options{Russian: true, HighEntropy: true}

// FuzzRedactText checks the invariants of Find and RedactText on any input: spans are ordered,
// in bounds, non-overlapping and of a known kind; a plain span's value is the text it cuts;
// redaction keeps UTF-8 valid and leaves everything between spans as it was.
func FuzzRedactText(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	e := newEngine(f, fuzzOptions)
	kinds := Kinds()
	f.Fuzz(func(t *testing.T, text string) {
		spans := e.Find(text)
		last := 0
		for _, s := range spans {
			if s.Start < last || s.End <= s.Start || s.End > len(text) {
				t.Fatalf("bad span %d:%d after %d in %d bytes", s.Start, s.End, last, len(text))
			}
			if !slices.Contains(kinds, s.Finding.Kind) {
				t.Fatalf("unknown kind %q", s.Finding.Kind)
			}
			if raw := text[s.Start:s.End]; !strings.Contains(raw, `\`) && s.Finding.Value != raw {
				t.Fatalf("value %q differs from the text it cuts, %q", s.Finding.Value, raw)
			}
			last = s.End
		}
		const mark = "\x01"
		got := e.RedactText(text, ReplacerFunc(func(Finding) string { return mark }))
		var want strings.Builder
		last = 0
		for _, s := range spans {
			want.WriteString(text[last:s.Start])
			want.WriteString(mark)
			last = s.End
		}
		want.WriteString(text[last:])
		if got != want.String() {
			t.Fatalf("RedactText = %q, want %q", got, want.String())
		}
		if utf8.ValidString(text) && !utf8.ValidString(e.RedactString(text, Marker{})) {
			t.Fatal("redaction broke UTF-8")
		}
	})
}

// FuzzRedactJSON checks that RedactJSON keeps a valid document valid and of the same shape,
// rejects an invalid one, and never hands a replacer an empty value.
func FuzzRedactJSON(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		raw, err := json.Marshal(map[string]any{"text": seed, "password": seed, "list": []string{seed}})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
		f.Add([]byte(seed))
	}
	e := newEngine(f, fuzzOptions)
	f.Fuzz(func(t *testing.T, data []byte) {
		empty := false
		out, err := e.RedactJSON(data, ReplacerFunc(func(f Finding) string {
			if f.Value == "" {
				empty = true
			}
			return MarkerText(f.Kind)
		}))
		if !json.Valid(data) {
			if err == nil {
				t.Fatalf("invalid JSON accepted: %q", data)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid JSON rejected: %v", err)
		}
		if !json.Valid(out) {
			t.Fatalf("output is not valid JSON: %q -> %q", data, out)
		}
		if empty {
			t.Fatal("a replacer got an empty value")
		}
		if shape(t, data) != shape(t, out) {
			t.Fatalf("top-level shape changed: %q -> %q", data, out)
		}
		inNames, outNames := memberNames(t, data), memberNames(t, out)
		var in, decoded any
		_ = json.Unmarshal(data, &in)
		_ = json.Unmarshal(out, &decoded)
		if countMembers(in) == len(inNames) && countMembers(decoded) != len(inNames) {
			t.Fatalf("members lost: %q -> %q", data, out)
		}
		kept := map[string]bool{}
		for _, n := range outNames {
			kept[n] = true
		}
		for _, n := range inNames {
			if len(e.Find(n)) > 0 && kept[n] {
				t.Fatalf("a name with a finding survived: %q in %q", n, out)
			}
		}
	})
}

// memberNames lists every member name of a JSON document, duplicates included.
func memberNames(t *testing.T, data []byte) []string {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	type level struct{ object, expectKey bool }
	var stack []level
	var names []string
	for {
		tok, err := d.Token()
		if err != nil {
			return names
		}
		top := len(stack) - 1
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if top >= 0 && stack[top].object {
					stack[top].expectKey = true
				}
				stack = append(stack, level{object: v == '{', expectKey: v == '{'})
			default:
				stack = stack[:top]
			}
		case string:
			if top >= 0 && stack[top].object && stack[top].expectKey {
				names = append(names, v)
				stack[top].expectKey = false
				continue
			}
			if top >= 0 && stack[top].object {
				stack[top].expectKey = true
			}
		default:
			if top >= 0 && stack[top].object {
				stack[top].expectKey = true
			}
		}
	}
}

// shape names the JSON type of a document's top-level value; a number may become a string only
// below the top level.
func shape(t *testing.T, data []byte) string {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("%q does not decode: %v", data, err)
	}
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "bool"
	default:
		return "null"
	}
}

// FuzzKeyLineRegions checks that the next-line key-value rule finds the same spans when it
// matches only the regions keyLineRegions returns as when it matches the whole text.
func FuzzKeyLineRegions(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	e := newEngine(f, Options{})
	var regional *rule
	for _, r := range e.rules {
		if r.priority == priorityKeyValueNextLine {
			regional = r
		}
	}
	whole := *regional
	whole.regions = nil
	f.Fuzz(func(t *testing.T, text string) {
		masked := maskEscapedBreaks(text)
		got := e.ruleSpans(regional, masked)
		var want []span
		if containsAny(strings.ToLower(masked), keyValuePrefilter) {
			want = e.ruleSpans(&whole, masked)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("regions give %+v, the whole text %+v", got, want)
		}
	})
}
