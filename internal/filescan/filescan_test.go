package filescan

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

const testKey = "test-escrow-key-0123456789abcdef"

var markerRE = regexp.MustCompile(`\[REDACTED:file #(k[a-z2-7]{10})\]`)

// fake builds a made-up credential from a prefix and filler, so that no literal in this file
// looks like one.
func fake(prefix string, n int) string { return prefix + strings.Repeat("aB3", n/3+1)[:n] }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type fixture struct {
	dir     string
	scanner *Scanner
	escrow  *escrow.Escrow
	start   time.Time
}

func newFixture(t *testing.T, maxBytes int64, keep bool) *fixture {
	t.Helper()
	engine, err := redact.New(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: t.TempDir(), start: time.Now(), escrow: escrow.New(escrow.Options{KeyHash: sha256.Sum256([]byte(testKey))})}
	o := Options{Server: "chat", Tools: []string{"download_media", "download_attachment"}, Roots: []string{f.dir}, MaxBytes: maxBytes, Engine: engine}
	if keep {
		o.Keep = f.escrow.KeepFile
	}
	f.scanner = New(o)
	return f
}

func (f *fixture) scan(t *testing.T, tool string, args map[string]any, res *mcp.CallToolResult) (*mcp.CallToolResult, int, error) {
	t.Helper()
	return f.scanner.Scan(t.Context(), tool, func() map[string]any { return args }, res, f.start)
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("first block is %T", res.Content[0])
	}
	return tc.Text
}

func get(t *testing.T, e *escrow.Escrow, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestFileWithSecretsIsWithheld(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	envFile := filepath.Join(f.dir, "telegram_1_2_3.txt")
	content := "DB_HOST=db\nDB_PASS" + "WORD=" + "hunter2!x\n"
	writeFile(t, envFile, content)

	// A text result, as a messenger download tool writes it.
	in := textResult("Media downloaded to " + envFile + ".")
	res, n, err := f.scan(t, "download_media", map[string]any{"chat_id": float64(1), "message_id": float64(2)}, in)
	if err != nil || n != 1 {
		t.Fatalf("scan = %d, %v", n, err)
	}
	got := text(t, res)
	m := markerRE.FindStringSubmatch(got)
	if m == nil || strings.Contains(got, envFile) || !strings.Contains(got, "file_name=telegram_1_2_3.txt") ||
		!strings.Contains(got, "contains: password") || !strings.Contains(got, "the owner can release it") {
		t.Fatalf("text = %q", got)
	}
	if text(t, in) != "Media downloaded to "+envFile+"." {
		t.Error("the input result was modified")
	}
	code, body := get(t, f.escrow, escrow.Route+m[1]+"/meta")
	var meta map[string]any
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatal(code, body)
	}
	if meta["kind"] != "file" || meta["file_name"] != "telegram_1_2_3.txt" || meta["size"] != float64(len(content)) ||
		!strings.Contains(body, `"source":{"chat_id":1,"message_id":2}`) || strings.Contains(body, f.dir) {
		t.Fatalf("meta = %s", body)
	}
	if code, body := get(t, f.escrow, escrow.Route+m[1]); code != http.StatusOK || body != content {
		t.Fatalf("value = %d %q", code, body)
	}

	// A structured result: the path member becomes the marker, so the schema still holds.
	gcFile := filepath.Join(f.dir, ".env")
	writeFile(t, gcFile, "export GITHUB_TOKEN="+fake("ghp_", 36)+"\n")
	structured := map[string]any{"path": gcFile, "file_name": ".env", "bytes": float64(50), "nested": []any{map[string]any{"deep": "at " + gcFile}}}
	raw, err := json.Marshal(structured)
	if err != nil {
		t.Fatal(err)
	}
	res, _, err = f.scan(t, "download_attachment", nil, &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, StructuredContent: structured})
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), gcFile) || !markerRE.Match(out) || strings.Contains(text(t, res), gcFile) {
		t.Errorf("structured = %s, text = %s", out, text(t, res))
	}
	if structured["path"] != gcFile {
		t.Error("the input structured content was modified")
	}

	// Nested path members and file:// links are found.
	nested := filepath.Join(f.dir, "nested.env")
	writeFile(t, nested, "API_TOKEN="+fake("", 30)+"\n")
	res, n, err = f.scan(t, "download_attachment", nil, &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.ResourceLink{URI: "file://" + nested, Name: "nested"}},
		StructuredContent: map[string]any{"file": map[string]any{"path": nested}},
	})
	if err != nil || n != 1 {
		t.Fatalf("nested: %d, %v", n, err)
	}
	if out, err = json.Marshal(res); err != nil || strings.Contains(string(out), nested) {
		t.Errorf("nested = %s, %v", out, err)
	}
}

func TestOnlyFilesTheToolWroteAreRead(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	outside := t.TempDir()
	tokens := filepath.Join(outside, "tokens.env")
	writeFile(t, tokens, "MCP_TOK"+"EN="+"abcdef123456\n")
	link := filepath.Join(f.dir, "link.env")
	if err := os.Symlink(tokens, link); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.dir, "orig.env"), "HARD_PASS"+"WORD="+"hard-pass-1\n")
	hard := filepath.Join(f.dir, "hard.env")
	if err := os.Link(filepath.Join(f.dir, "orig.env"), hard); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(f.dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{tokens, link, hard, sub, f.dir, filepath.Join(f.dir, "missing.env"), filepath.Join(f.dir, "sub", "..", "..", filepath.Base(outside), "tokens.env")} {
		in := textResult("Media downloaded to " + path + ".")
		res, n, err := f.scanner.Scan(t.Context(), "download_media", func() map[string]any { return map[string]any{"file_path": path} }, in, f.start)
		if err != nil || n != 0 || text(t, res) != text(t, in) {
			t.Errorf("%s was scanned: %q, %d, %v", path, text(t, res), n, err)
		}
	}
	// A path only the arguments name must have changed after the call started, without slack.
	argOnly := filepath.Join(f.dir, "arg.env")
	writeFile(t, argOnly, "ARG_PASS"+"WORD="+"arg-pass-1\n")
	in := textResult("done")
	if _, n, err := f.scanner.Scan(t.Context(), "download_media", func() map[string]any { return map[string]any{"output_path": argOnly} }, in, time.Now().Add(time.Second)); err != nil || n != 0 {
		t.Errorf("an argument path written before the call = %d, %v", n, err)
	}
	if _, n, err := f.scan(t, "download_media", map[string]any{"output_path": argOnly}, in); err != nil || n != 1 {
		t.Errorf("an argument path written during the call = %d, %v", n, err)
	}
}

// TestCachedDownload checks that a file the result names is scanned even when it was written
// before the call, as a download tool that caches its files reports the same path again.
func TestCachedDownload(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	cached := filepath.Join(f.dir, "cached.env")
	writeFile(t, cached, "OLD_PASS"+"WORD="+"old-pass-1\n")
	in := textResult("Media downloaded to " + cached + ".")
	later := time.Now().Add(time.Minute) // the inode changed long before this call started
	res, n, err := f.scanner.Scan(t.Context(), "download_media", nil, in, later)
	if err != nil || n != 1 || strings.Contains(text(t, res), cached) {
		t.Errorf("a cached file = %q, %d, %v", text(t, res), n, err)
	}
	if !markerRE.MatchString(text(t, res)) {
		t.Errorf("a cached file is not kept: %q", text(t, res))
	}
	// A file that predates the gate, as a cache kept across a restart, is withheld but not kept.
	o := f.scanner.o
	o.Started = time.Now().Add(time.Minute)
	res, n, err = New(o).Scan(t.Context(), "download_media", nil, in, later)
	if got := text(t, res); err != nil || n != 1 || strings.Contains(got, cached) || markerRE.MatchString(got) ||
		!strings.HasPrefix(got, "[REDACTED:file] ") || strings.Contains(got, "release") {
		t.Errorf("a file older than the gate = %q, %d, %v", got, n, err)
	}
}

// TestLongLineStaysCheap checks that a text built to make the search for unquoted paths slow
// costs a bounded number of file lookups.
func TestLongLineStaysCheap(t *testing.T) {
	t.Parallel()
	for _, line := range []string{
		strings.Repeat("saved to /a ", 3<<20/12),
		"saved to /a" + strings.Repeat(" w", 2<<20),
	} {
		lookups := 0
		begin := time.Now()
		_, _ = candidates(nil, textResult(line), func(string) bool { lookups++; return false })
		// The time bound only catches quadratic work, which took minutes on such a line; the race
		// detector makes the linear scan of a few MiB take seconds.
		if lookups > (maxCandidates+1)*maxPathWords || time.Since(begin) > time.Minute {
			t.Errorf("%d lookups in %v", lookups, time.Since(begin))
		}
	}
	if _, overflow := candidates(nil, textResult(strings.Repeat("saved to /a ", maxMentions+1)), nil); !overflow {
		t.Error("more than maxMentions mentions do not overflow")
	}
	// The budget is per call: many content items, each under the limit, still overflow it.
	res := &mcp.CallToolResult{}
	item := strings.Repeat("saved to /r/x"+strings.Repeat(" w", maxPathWords)+"\n", maxMentions)
	for range 64 {
		res.Content = append(res.Content, &mcp.TextContent{Text: item})
	}
	lookups := 0
	if _, overflow := candidates(nil, res, func(string) bool { lookups++; return false }); !overflow || lookups > maxLookups {
		t.Errorf("many items: overflow %v after %d lookups", overflow, lookups)
	}
	// 64 mentions with long tails stay within the lookup budget and pass.
	var b strings.Builder
	for i := range maxMentions {
		fmt.Fprintf(&b, "saved to /r/x%d%s\n", i, strings.Repeat(" w", 2*maxPathWords))
	}
	lookups = 0
	if _, overflow := candidates(nil, textResult(b.String()), func(string) bool { lookups++; return false }); overflow || lookups > maxLookups {
		t.Errorf("64 long mentions: overflow %v after %d lookups", overflow, lookups)
	}
}

// TestUnquotedPathWithSpaces checks that an unquoted path after "downloaded to" may hold
// spaces: the longest part of the line that names a file is taken.
func TestUnquotedPathWithSpaces(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	if err := os.Mkdir(filepath.Join(f.dir, "my"), 0o700); err != nil {
		t.Fatal(err)
	}
	spaced := filepath.Join(f.dir, "my report.env")
	writeFile(t, spaced, "DB_PASS"+"WORD="+"hunter2!x\n")
	for _, line := range []string{
		"Downloaded to " + spaced,
		"Downloaded to " + spaced + ". Open it with care",
		"Saved to " + spaced + " (12 bytes)\nnext line",
	} {
		in := textResult(line)
		res, n, err := f.scan(t, "download_media", nil, in)
		if err != nil || n != 1 || strings.Contains(text(t, res), spaced) {
			t.Errorf("%q = %q, %d, %v", line, text(t, res), n, err)
		}
	}
}

func TestFilesThatPass(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	plain := filepath.Join(f.dir, "notes.txt")
	writeFile(t, plain, "nothing secret here\n")
	binary := filepath.Join(f.dir, "photo.jpg")
	writeFile(t, binary, "\xff\xd8\xff\x00binary DB_PASS"+"WORD="+"hunter2!x")
	secret := filepath.Join(f.dir, ".env")
	writeFile(t, secret, "DB_PASS"+"WORD="+"hunter2!x\n")
	for _, c := range []struct{ tool, path string }{
		{"download_media", plain}, {"download_media", binary}, {"get_messages", secret},
	} {
		in := textResult("Media downloaded to " + c.path + ".")
		res, n, err := f.scan(t, c.tool, nil, in)
		if err != nil || n != 0 || text(t, res) != text(t, in) {
			t.Errorf("%s %s changed: %q, %d, %v", c.tool, c.path, text(t, res), n, err)
		}
	}
	errResult := textResult("Media downloaded to " + secret + ".")
	errResult.IsError = true
	if res, n, err := f.scan(t, "download_media", nil, errResult); err != nil || n != 0 || res != errResult {
		t.Error("a tool error was scanned")
	}
}

func TestCredentialStoreIsWithheld(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, false)
	p12 := filepath.Join(f.dir, "cert.p12")
	writeFile(t, p12, "\x30\x82\x00binary")
	res, n, err := f.scan(t, "download_media", nil, textResult("Media downloaded to "+p12+"."))
	got := text(t, res)
	if err != nil || n != 1 || !strings.HasPrefix(got, "[REDACTED:file] ") || !strings.Contains(got, "contains: secret_file") ||
		strings.Contains(got, "release") {
		t.Errorf("a credential store without an escrow = %q, %d, %v", got, n, err)
	}
}

func TestUnscannableFilesFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 1024, true)
	bigText := filepath.Join(f.dir, "big.log")
	writeFile(t, bigText, strings.Repeat("line of text\n", 200))
	bigUnnamed := filepath.Join(f.dir, "big.bin")
	writeFile(t, bigUnnamed, strings.Repeat("plain text without a text name\n", 100))
	bigStore := filepath.Join(f.dir, "big.kdbx")
	writeFile(t, bigStore, "\x00"+strings.Repeat("x", 2000))
	notUTF8 := filepath.Join(f.dir, "latin1.txt")
	writeFile(t, notUTF8, "pass\xe9word: hunter2!x\n")
	unreadable := filepath.Join(f.dir, "locked.env")
	writeFile(t, unreadable, "DB_PASS"+"WORD="+"hunter2!x\n")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	cases := []string{bigText, bigUnnamed, bigStore, notUTF8}
	if os.Geteuid() != 0 {
		cases = append(cases, unreadable)
	}
	for _, path := range cases {
		res, _, err := f.scan(t, "download_media", nil, textResult("Media downloaded to "+path+"."))
		if !errors.Is(err, ErrUnscannable) || res != nil || strings.Contains(err.Error(), f.dir) {
			t.Errorf("%s: %v, %v; want ErrUnscannable without the path", filepath.Base(path), res, err)
		}
	}
	bigBinary := filepath.Join(f.dir, "video.mp4")
	writeFile(t, bigBinary, "\x00\x00\x00\x18ftyp"+strings.Repeat("\x00\xff", 2000))
	in := textResult("Media downloaded to " + bigBinary + ".")
	if res, n, err := f.scan(t, "download_media", nil, in); err != nil || n != 0 || text(t, res) != text(t, in) {
		t.Errorf("a large binary file = %d, %v", n, err)
	}
}

func TestCandidates(t *testing.T) {
	t.Parallel()
	res := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: `Saved to "/d/a b.txt"; written to '/d/c.txt', downloaded to /d/e.txt.`},
			&mcp.TextContent{Text: `{"items":[{"localPath":"/d/f.txt"}],"path":"relative.txt"}`},
			&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "file:///d/g%20h.txt"}},
		},
		StructuredContent: map[string]any{"saved_to": "/d/i.txt"},
	}
	got := map[string]bool{}
	cands, overflow := candidates(map[string]any{"output_path": "/d/j.txt", "path": "/d/e.txt"}, res, nil)
	if overflow {
		t.Error("overflow")
	}
	for _, c := range cands {
		got[c.path] = c.fromArguments
	}
	want := map[string]bool{
		"/d/a b.txt": false, "/d/c.txt": false, "/d/e.txt": false, "/d/f.txt": false,
		"/d/g h.txt": false, "/d/i.txt": false, "/d/j.txt": true,
	}
	if len(got) != len(want) {
		t.Errorf("candidates = %v, want %v", got, want)
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("candidate %s = %v (present %v), want fromArguments %v", k, g, ok, v)
		}
	}
}

func TestTooManyPathsFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	var b strings.Builder
	for i := range maxCandidates + 1 {
		b.WriteString("saved to /x/" + strings.Repeat("a", i+1) + " ")
	}
	if _, _, err := f.scan(t, "download_media", nil, textResult(b.String())); !errors.Is(err, ErrUnscannable) {
		t.Errorf("too many paths = %v, want ErrUnscannable", err)
	}
}

func TestUnresolvablePathUnderRootFailsClosed(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	f := newFixture(t, 0, true)
	locked := filepath.Join(f.dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(locked, "a.env"), "DB_PASS"+"WORD="+"hunter2!x\n")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec // a directory needs x to be removed
	_, _, err := f.scan(t, "download_media", nil, textResult("Media downloaded to "+filepath.Join(locked, "a.env")+"."))
	if !errors.Is(err, ErrUnscannable) {
		t.Errorf("a path under a root that cannot be resolved = %v, want ErrUnscannable", err)
	}
}

func TestEmbeddedTextMentionIsWithheld(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	p := filepath.Join(f.dir, "a.env")
	writeFile(t, p, "DB_PASS"+"WORD="+"hunter2!x\n")
	res, n, err := f.scan(t, "download_media", nil, &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: "Media downloaded to " + p + "."},
		&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "note://1", MIMEType: "text/plain", Text: "stored at " + p}},
	}})
	if err != nil || n != 1 {
		t.Fatalf("scan = %d, %v", n, err)
	}
	if _, ok := res.Content[1].(*mcp.TextContent); !ok {
		t.Errorf("the embedded resource naming the file was kept: %#v", res.Content[1])
	}
}

func TestMetaMentionIsWithheld(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	p := filepath.Join(f.dir, "a.env")
	writeFile(t, p, "DB_PASS"+"WORD="+"hunter2!x\n")
	in := &mcp.CallToolResult{
		Meta: mcp.Meta{"download": map[string]any{"saved": []any{"at " + p}}, "other": "kept"},
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Media downloaded to " + p + "."},
			&mcp.ImageContent{MIMEType: "image/png", Data: []byte{1}, Meta: mcp.Meta{"source": p}},
			&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "note://1", Text: "note", Meta: mcp.Meta{"file": p}}},
			&mcp.TextContent{Text: "unrelated", Meta: mcp.Meta{"x": "y"}},
		},
	}
	res, n, err := f.scan(t, "download_media", nil, in)
	if err != nil || n != 1 {
		t.Fatalf("scan = %d, %v", n, err)
	}
	out, err := json.Marshal(res)
	if err != nil || strings.Contains(string(out), p) {
		t.Fatalf("result = %s, %v", out, err)
	}
	for i := 1; i <= 2; i++ {
		if _, ok := res.Content[i].(*mcp.TextContent); !ok {
			t.Errorf("block %d, whose _meta names the file, was kept: %#v", i, res.Content[i])
		}
	}
	if tc, ok := res.Content[3].(*mcp.TextContent); !ok || tc.Text != "unrelated" {
		t.Errorf("an unrelated block changed: %#v", res.Content[3])
	}
	if res.Meta["other"] != "kept" || !markerRE.MatchString(fmt.Sprint(res.Meta["download"])) {
		t.Errorf("result _meta = %v", res.Meta)
	}
	if in.Meta["download"].(map[string]any)["saved"].([]any)[0] != "at "+p { //nolint:forcetypeassert // built above
		t.Error("the input _meta was modified")
	}
}

func TestPathThroughAFileFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 0, true)
	p := filepath.Join(f.dir, "a.txt")
	writeFile(t, p, "plain\n")
	_, _, err := f.scan(t, "download_media", nil, textResult("Media downloaded to "+filepath.Join(p, "x")+"."))
	if !errors.Is(err, ErrUnscannable) {
		t.Errorf("a path through a file under a root = %v, want ErrUnscannable", err)
	}
}

func TestUnquotedPath(t *testing.T) {
	t.Parallel()
	files := map[string]bool{"/d/my report.env": true, "/d/a": true}
	isFile := func(p string) bool { return files[p] }
	for _, c := range []struct{ tail, want string }{
		{"/d/my report.env", "/d/my report.env"},
		{"/d/my report.env. Done", "/d/my report.env"},
		{"/d/my  report.env", "/d/my"},
		{"/d/a b c", "/d/a"},
		{"/d/none here", "/d/none"},
		{"/d/x" + strings.Repeat(" w", 40) + " /d/my report.env", "/d/x"},
	} {
		if got := unquotedPath(c.tail, isFile); got != c.want {
			t.Errorf("unquotedPath(%q) = %q, want %q", c.tail, got, c.want)
		}
	}
	if got := unquotedPath("/d/my report.env", nil); got != "/d/my" {
		t.Errorf("without isFile = %q", got)
	}
}
