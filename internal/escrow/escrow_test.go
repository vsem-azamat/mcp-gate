package escrow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/testkit"
)

func TestMain(m *testing.M) {
	runSocketClient() // the test binary as a socket client, for the process-tree tests
	goleak.VerifyTestMain(m)
}

const testKey = "test-escrow-key-0123456789abcdef"

func testHash() [sha256.Size]byte { return sha256.Sum256([]byte(testKey)) }

var markerRE = regexp.MustCompile(`\[REDACTED:([a-z_]+) #(k[a-z2-7]{10})\]`)

// fakeClock is a settable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func withClock(s *store) *fakeClock {
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.now = c.now
	return c
}

func request(t *testing.T, e *Escrow, method, path, auth string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHandleFormat(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 200 {
		h, err := newHandle()
		if err != nil {
			t.Fatal(err)
		}
		if !HandleRE.MatchString(h) || seen[h] {
			t.Fatalf("handle %q: malformed or repeated", h)
		}
		seen[h] = true
	}
}

func TestPreview(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]string{
		"AKIAIOSFODNN7EXAMPLEX2Q": "AKIA…X2Q",
		"hunter2!x":               "hu…x",
		"hunter2":                 "…",
		"пароль-секретный":        "паро…ный",
		"\xff\xfe-not-utf8-value": "…",
	} {
		if got := preview([]byte(value)); got != want {
			t.Errorf("preview(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestParseKeyHash(t *testing.T) {
	t.Parallel()
	h := testHash()
	good := hex.EncodeToString(h[:])
	for _, s := range []string{good, strings.ToUpper(good), " " + good + "\n"} {
		if got, err := ParseKeyHash(s); err != nil || got != h {
			t.Errorf("ParseKeyHash(%q) = %x, %v", s, got, err)
		}
	}
	for _, bad := range []string{"", "zz", strings.Repeat("a", 63), good + "00"} {
		if _, err := ParseKeyHash(bad); err == nil || (len(bad) > 2 && strings.Contains(err.Error(), bad)) {
			t.Errorf("ParseKeyHash(%q) = %v", bad, err)
		}
	}
}

func TestStoreExpiryDedupAndEviction(t *testing.T) {
	t.Parallel()
	s := newStore(2, slog.New(slog.DiscardHandler))
	clk := withClock(s)
	a, _ := s.insert(&entry{kind: "password", value: []byte("one"), dedupKey: "d1"}, time.Hour)
	again, _ := s.insert(&entry{kind: "password", value: []byte("one"), dedupKey: "d1"}, time.Hour)
	if a != again {
		t.Fatalf("the same secret got two handles: %s, %s", a, again)
	}
	clk.add(time.Second)
	b, _ := s.insert(&entry{kind: "password", value: []byte("two")}, time.Hour)
	clk.add(time.Second)
	c, _ := s.insert(&entry{kind: "password", value: []byte("three")}, time.Hour)
	if _, ok := s.get(a); ok {
		t.Fatal("the oldest entry was not evicted")
	}
	if _, ok := s.get(b); !ok {
		t.Fatal("entry b is missing")
	}
	clk.add(2 * time.Hour)
	if _, ok := s.get(c); ok {
		t.Fatal("an expired entry is readable")
	}
	if s.remove(b) {
		t.Fatal("removing an expired entry reports it live")
	}
}

func TestRepeatExtendsExpiry(t *testing.T) {
	t.Parallel()
	s := newStore(10, slog.New(slog.DiscardHandler))
	clk := withClock(s)
	h, _ := s.insert(&entry{kind: "password", value: []byte("one"), dedupKey: "d"}, time.Hour)
	clk.add(59 * time.Minute)
	_, _ = s.insert(&entry{kind: "password", value: []byte("one"), dedupKey: "d"}, time.Hour)
	clk.add(30 * time.Minute)
	if _, ok := s.get(h); !ok {
		t.Fatal("a secret seen again must keep its handle alive")
	}
}

func TestTotalBytesCap(t *testing.T) {
	t.Parallel()
	s := newStore(100000, slog.New(slog.DiscardHandler))
	big := strings.Repeat("x", MaxValueBytes)
	for i := range 2 * MaxTotalBytes / MaxValueBytes {
		if _, err := s.insert(&entry{kind: "k", value: []byte(big + strconv.Itoa(i))}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if s.totalBytes > MaxTotalBytes {
		t.Fatalf("totalBytes = %d, cap %d", s.totalBytes, MaxTotalBytes)
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()
	s := newStore(10, slog.New(slog.DiscardHandler))
	clk := withClock(s)
	_, _ = s.insert(&entry{kind: "k", value: []byte("v")}, time.Minute)
	clk.add(time.Minute)
	s.sweep()
	if len(s.entries) != 0 || s.totalBytes != 0 {
		t.Fatalf("after the sweep: %d entries, %d bytes", len(s.entries), s.totalBytes)
	}
}

func TestReplacer(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash()})
	args := map[string]any{"chat_id": float64(42), "message_ids": []any{float64(7)}, "text": "password: x", "query": "secret"}
	r := e.Replacer(Source{Server: "chat", Tool: "get_messages", TTL: time.Hour, Arguments: func() map[string]any { return args }})
	m := markerRE.FindStringSubmatch(r.Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"}))
	if m == nil || m[1] != "password" {
		t.Fatalf("marker = %v", m)
	}
	if again := markerRE.FindStringSubmatch(r.Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"})); again[2] != m[2] {
		t.Error("the same secret got two handles")
	}
	if other := e.Replacer(Source{Server: "mail"}).Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"}); strings.Contains(other, m[2]) {
		t.Error("another server shares the handle")
	}
	ent, ok := e.store.get(m[2])
	if !ok || string(ent.value) != "Qwerty-12345" || ent.tool != "get_messages" || ent.server != "chat" ||
		ent.source["chat_id"] != float64(42) || ent.source["text"] != nil || ent.expires.Sub(ent.created).Round(time.Minute) != time.Hour {
		t.Fatalf("entry = %+v", ent)
	}
	if got := r.Replace(redact.Finding{Kind: "private_key", Value: strings.Repeat("k", MaxValueBytes+1)}); got != "[REDACTED:private_key]" {
		t.Errorf("an oversized value = %q, want the plain marker", got)
	}
}

func TestStats(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash()})
	r := e.Replacer(Source{Server: "chat"})
	marker := r.Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"})
	r.Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"})                                  // the same handle
	e.Replacer(Source{Server: "mail"}).Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"}) // another server's
	m := markerRE.FindStringSubmatch(marker)
	request(t, e, http.MethodGet, Route+m[2], "Bearer wrong")
	request(t, e, http.MethodGet, Route+m[2], "")
	request(t, e, http.MethodGet, Route+m[2], "Bearer "+testKey)
	if st := e.Stats(); st != (Stats{Entries: 2, Stored: 2, AuthFailures: 2}) {
		t.Errorf("stats %+v", st)
	}
	request(t, e, http.MethodDelete, Route+m[2], "Bearer "+testKey)
	if st := e.Stats(); st.Entries != 1 || st.Stored != 2 {
		t.Errorf("stats after a delete %+v", st)
	}
}

func TestDiscardDropsOnlyTheWithheldResultsEntries(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash()})
	handle := func(r *Replacer, value string) string {
		t.Helper()
		m := markerRE.FindStringSubmatch(r.Replace(redact.Finding{Kind: "password", Value: value}))
		if m == nil {
			t.Fatalf("no marker for %q", value)
		}
		return m[2]
	}
	shown := e.Replacer(Source{Server: "chat"})
	old := handle(shown, "Shown-Before-1")

	withheld := e.Replacer(Source{Server: "chat"})
	own := handle(withheld, "Only-In-Withheld-2")
	again := handle(withheld, "Only-In-Withheld-2")
	reused := handle(withheld, "Shown-Before-1")
	shared := handle(withheld, "Shared-Later-3")
	if own != again || reused != old {
		t.Fatal("dedup changed")
	}
	// Another result shows the third value after the withheld one kept it.
	if handle(e.Replacer(Source{Server: "chat"}), "Shared-Later-3") != shared {
		t.Fatal("dedup changed")
	}

	withheld.Discard()
	if _, ok := e.store.get(own); ok {
		t.Error("an entry only the withheld result used is still kept")
	}
	if _, ok := e.store.get(old); !ok {
		t.Error("an entry kept before the withheld result was dropped")
	}
	if _, ok := e.store.get(shared); !ok {
		t.Error("an entry another result used was dropped")
	}
	if e.store.totalBytes != len("Shown-Before-1")+len("Shared-Later-3") {
		t.Errorf("totalBytes = %d", e.store.totalBytes)
	}
	withheld.Discard() // a second call is harmless
}

func TestIssuedKeepsNothing(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash()})
	r := e.Replacer(Source{Server: "chat"})
	seen := redact.Finding{Kind: "password", Value: "Seen-In-Result-1"}
	marker := r.Replace(seen)
	if again := r.Replace(seen); again != marker || len(r.handles) != 1 {
		t.Fatalf("a repeated value = %q, %d handles", again, len(r.handles))
	}
	is := r.Issued()
	if got := is.Replace(seen); got != marker {
		t.Errorf("Issued for a replaced value = %q, want %q", got, marker)
	}
	unseen := redact.Finding{Kind: "github_token", Value: "Never-In-Result-2"}
	if got := is.Replace(unseen); got != unseen.Value {
		t.Errorf("Issued for another value = %q", got)
	}
	if len(e.store.entries) != 1 || len(r.handles) != 1 {
		t.Errorf("%d entries, %d handles after Issued", len(e.store.entries), len(r.handles))
	}
}

func TestHTTPContract(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash()})
	secret := "AKIA" + "IOSFODNN7EXAMPLEX2Q"
	marker := e.Replacer(Source{
		Server: "chat", Tool: "get_messages", TTL: time.Hour,
		Arguments: func() map[string]any {
			return map[string]any{"chat_id": float64(42), "message_ids": []any{float64(7)}, "text": "password: x"}
		},
	}).Replace(redact.Finding{Kind: "aws_access_key", Value: secret})
	m := markerRE.FindStringSubmatch(marker)
	if m == nil {
		t.Fatalf("marker = %q", marker)
	}
	srv := httptest.NewServer(e.Handler())
	defer srv.Close()
	testkit.CheckEscrowContract(t, testkit.EscrowTarget{
		Base: srv.URL, Key: testKey, Handle: m[2], Secret: secret, TTL: time.Hour,
		Meta: map[string]any{
			"type": "aws_access_key", "server": "chat", "tool": "get_messages", "preview": "AKIA…X2Q",
			"source": map[string]any{"chat_id": float64(42), "message_ids": []any{float64(7)}},
		},
	})
}

func TestFileEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := []byte("DB_PASS" + "WORD=" + "hunter2!x\n")
	if err := os.WriteFile(filepath.Join(dir, "a.env"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(Options{KeyHash: testHash()})
	handle, err := e.KeepFile(File{
		Source: Source{Server: "chat", Tool: "download_media", Arguments: func() map[string]any { return map[string]any{"chat_id": "c1"} }},
		Root:   dir, Rel: "a.env", Name: "a.env", Size: int64(len(content)), Hash: sha256.Sum256(content), Kinds: []string{"env_secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := "Bearer " + testKey
	rec := request(t, e, http.MethodGet, Route+handle+"/meta", auth)
	if strings.Contains(rec.Body.String(), dir) {
		t.Error("meta reveals the path")
	}
	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["kind"] != "file" || meta["type"] != "file" || meta["file_name"] != "a.env" || meta["size"] != float64(len(content)) ||
		meta["preview"] != "" || meta["tool"] != "download_media" {
		t.Fatalf("meta = %s", rec.Body)
	}
	if rec = request(t, e, http.MethodGet, Route+handle, auth); rec.Code != http.StatusOK || rec.Body.String() != string(content) {
		t.Fatalf("value = %d %q", rec.Code, rec.Body)
	}
	// A file that changed after the scan, or was replaced by a symlink, is not served.
	if err := os.WriteFile(filepath.Join(dir, "a.env"), []byte("DB_PASS"+"WORD="+"hunter3!x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec = request(t, e, http.MethodGet, Route+handle, auth); rec.Code != http.StatusNotFound {
		t.Errorf("a changed file = %d, want 404", rec.Code)
	}
	if err := os.Remove(filepath.Join(dir, "a.env")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "a.env")
	if err := os.WriteFile(other, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "a.env")); err != nil {
		t.Fatal(err)
	}
	if rec = request(t, e, http.MethodGet, Route+handle, auth); rec.Code != http.StatusNotFound {
		t.Errorf("a symlink = %d, want 404", rec.Code)
	}
}

func TestFailedAuthLimit(t *testing.T) {
	t.Parallel()
	client := "203.0.113.5"
	e := New(Options{KeyHash: testHash(), Remote: func(r *http.Request) string { return r.Header.Get("X-Client") }})
	clk := withClock(e.store)
	h, _ := e.store.insert(&entry{kind: "password", value: []byte("Qwerty-12345")}, 0)
	for i := range failBurst {
		if rec := request(t, e, http.MethodGet, Route+h, "Bearer wrong", "X-Client", client); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i+1, rec.Code)
		}
	}
	rec := request(t, e, http.MethodGet, Route+h, "Bearer wrong", "X-Client", client)
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != "Too Many Requests\n" ||
		rec.Header().Get("Retry-After") != "3" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("a wrong key over the limit = %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	// The client's bucket is checked before the key, so a guess that happens to be right is
	// refused too: guessing from one address is bounded.
	if rec := request(t, e, http.MethodGet, Route+h, "Bearer "+testKey, "X-Client", client); rec.Code != http.StatusTooManyRequests {
		t.Errorf("the right key over the limit = %d, want 429", rec.Code)
	}
	if rec := request(t, e, http.MethodGet, Route+h, "", "X-Client", client); rec.Code != http.StatusUnauthorized {
		t.Errorf("no key over the limit = %d, want 401", rec.Code)
	}
	if rec := request(t, e, http.MethodGet, Route+h, "Bearer "+testKey, "X-Client", "203.0.113.6"); rec.Code != http.StatusOK {
		t.Errorf("another client = %d, want 200", rec.Code)
	}
	clk.add(failRefill)
	if rec := request(t, e, http.MethodGet, Route+h, "Bearer "+testKey, "X-Client", client); rec.Code != http.StatusOK {
		t.Errorf("after a refill = %d, want 200", rec.Code)
	}
	if rec := request(t, e, http.MethodGet, Route+h, "Bearer wrong", "X-Client", client); rec.Code != http.StatusUnauthorized {
		t.Errorf("the earned attempt = %d, want 401", rec.Code)
	}
	if rec := request(t, e, http.MethodGet, Route+h, "Bearer wrong", "X-Client", client); rec.Code != http.StatusTooManyRequests {
		t.Errorf("after spending it = %d, want 429", rec.Code)
	}
}

func TestLimiterTableIsBounded(t *testing.T) {
	t.Parallel()
	c := &clock{now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	l := newLimiter(c)
	for range failBurst {
		l.fail("198.51.100.1") // the client that failed most
	}
	for i := range maxClients + 100 {
		l.global.tokens = globalBurst // the table alone, without the global bucket
		l.fail("client-" + strconv.Itoa(i))
	}
	if len(l.budgets) > maxClients {
		t.Fatalf("%d budgets, cap %d", len(l.budgets), maxClients)
	}
	if _, ok := l.allow("198.51.100.1"); ok {
		t.Error("a full table forgot the client that failed most")
	}
	if _, ok := l.allow("198.51.100.2"); !ok {
		t.Error("a client that never failed is refused")
	}
}

func TestGlobalFailLimit(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash(), Remote: func(r *http.Request) string { return r.Header.Get("X-Client") }})
	clk := withClock(e.store)
	h, _ := e.store.insert(&entry{kind: "password", value: []byte("Qwerty-12345")}, 0)
	get := func(auth, client string) int {
		t.Helper()
		return request(t, e, http.MethodGet, Route+h, auth, "X-Client", client).Code
	}
	owner := "192.0.2.1"
	if code := get("Bearer "+testKey, owner); code != http.StatusOK {
		t.Fatalf("the owner = %d, want 200", code)
	}
	// One guess from each of many addresses: no client bucket runs out, the global one does.
	for i := range globalBurst {
		if code := get("Bearer wrong", "198.51.100."+strconv.Itoa(i)); code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, code)
		}
	}
	rec := request(t, e, http.MethodGet, Route+h, "Bearer wrong", "X-Client", "203.0.113.9")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("another guess, global bucket empty = %d %v, want 429", rec.Code, rec.Header())
	}
	if code := get("", "203.0.113.11"); code != http.StatusUnauthorized {
		t.Errorf("a request without a key, global bucket empty = %d, want 401", code)
	}
	// The global bucket never refuses the right key, from a new client either.
	if code := get("Bearer "+testKey, "203.0.113.12"); code != http.StatusOK {
		t.Errorf("the right key from a new client, global bucket empty = %d, want 200", code)
	}
	// A trusted client's wrong key spends only its own bucket.
	if code := get("Bearer wrong", owner); code != http.StatusUnauthorized {
		t.Errorf("the trusted owner's wrong key, global bucket empty = %d, want 401", code)
	}
	// A wrong key refused by the empty global bucket still spends its client's bucket, so the
	// global bucket running out does not lift the bound on guessing from one address.
	guesser := "203.0.113.20"
	for i := range failBurst {
		if code := get("Bearer wrong", guesser); code != http.StatusTooManyRequests {
			t.Fatalf("guess %d, global bucket empty = %d, want 429", i+1, code)
		}
	}
	if code := get("Bearer "+testKey, guesser); code != http.StatusTooManyRequests {
		t.Errorf("the right key after guesses refused by the global bucket = %d, want 429", code)
	}
	clk.add(globalRefill)
	if code := get("Bearer wrong", "203.0.113.13"); code != http.StatusUnauthorized {
		t.Errorf("the earned guess = %d, want 401", code)
	}
	if code := get("Bearer wrong", "203.0.113.14"); code != http.StatusTooManyRequests {
		t.Errorf("after spending it = %d, want 429", code)
	}
}

// Concurrent wrong keys cannot share one global token: each is spent under the lock.
func TestGlobalTokensAreNotShared(t *testing.T) {
	t.Parallel()
	c := &clock{now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	l := newLimiter(c)
	var wg sync.WaitGroup
	var passed atomic.Int64
	for i := range globalBurst + 50 {
		wg.Go(func() {
			if _, ok := l.fail("198.51.100." + strconv.Itoa(i%250)); ok {
				passed.Add(1)
			}
		})
	}
	wg.Wait()
	if passed.Load() != globalBurst {
		t.Errorf("%d wrong keys counted, want %d", passed.Load(), globalBurst)
	}
}

func TestTrustedClientsAreBounded(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	c := &clock{now: func() time.Time { return now }}
	l := newLimiter(c)
	for i := range maxTrusted + 10 {
		now = start.Add(time.Duration(i) * time.Second)
		l.succeed("client-" + strconv.Itoa(i))
	}
	if len(l.trusted) != maxTrusted {
		t.Fatalf("%d trusted, cap %d", len(l.trusted), maxTrusted)
	}
	if l.isTrusted("client-0", now) {
		t.Error("the client that authenticated longest ago is kept")
	}
	if !l.isTrusted("client-"+strconv.Itoa(maxTrusted+9), now) {
		t.Error("the latest client is dropped")
	}
}

func TestLimiterGroupsIPv6(t *testing.T) {
	t.Parallel()
	c := &clock{now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	l := newLimiter(c)
	for i := range failBurst {
		l.fail("2001:db8:1:2::" + strconv.FormatInt(int64(i+1), 16))
	}
	if _, ok := l.allow("2001:db8:1:2:ffff::1"); ok {
		t.Error("another address of the same /64 is allowed")
	}
	if _, ok := l.allow("2001:db8:1:3::1"); !ok {
		t.Error("another /64 is refused")
	}
}

func TestAbsentKeyCostsNothing(t *testing.T) {
	t.Parallel()
	e := New(Options{KeyHash: testHash(), Remote: func(*http.Request) string { return "127.0.0.1" }})
	for range 3 * failBurst {
		for _, auth := range []string{"", "Basic dXNlcjpwYXNz", "Bearer ", testKey} {
			if rec := request(t, e, http.MethodGet, Route+"kaaaaaaaaaa", auth); rec.Code != http.StatusUnauthorized {
				t.Fatalf("auth %q = %d, want 401", auth, rec.Code)
			}
		}
	}
	if rec := request(t, e, http.MethodGet, Route+"kaaaaaaaaaa", "Bearer "+testKey); rec.Code != http.StatusNotFound {
		t.Errorf("the owner after requests without a key = %d, want 404", rec.Code)
	}
}

func TestSourceArguments(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"chat_id": float64(42), "ticket": "T-1", "repo": "server-a", "text": "password: x",
		"long": strings.Repeat("x", 201), "multi": "a\nb", "ids": []any{"a", float64(2), map[string]any{}},
	}
	sourceOf := func(e *Escrow) map[string]any {
		t.Helper()
		m := markerRE.FindStringSubmatch(e.Replacer(Source{Server: "s", Arguments: func() map[string]any { return args }}).
			Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"}))
		if m == nil {
			t.Fatal("no marker")
		}
		ent, _ := e.store.get(m[2])
		return ent.source
	}
	if got := sourceOf(New(Options{KeyHash: testHash()})); len(got) != 1 || got["chat_id"] != float64(42) {
		t.Errorf("default source = %v, want chat_id only", got)
	}
	got := sourceOf(New(Options{KeyHash: testHash(), SourceArguments: []string{"ticket", "repo", "long", "multi", "ids"}}))
	if ids, _ := got["ids"].([]any); len(got) != 3 || got["ticket"] != "T-1" || got["repo"] != "server-a" || len(ids) != 2 {
		t.Errorf("configured source = %v, want ticket, repo and two ids", got)
	}
	if got := sourceOf(New(Options{KeyHash: testHash(), SourceArguments: []string{}})); len(got) != 0 {
		t.Errorf("an empty list keeps %v, want nothing", got)
	}
	if !slices.Contains(DefaultSourceArguments, "chat_id") || len(DefaultSourceArguments) != 18 {
		t.Errorf("DefaultSourceArguments = %v", DefaultSourceArguments)
	}
}
