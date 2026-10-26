package escrow

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// shortDir returns a fresh directory with a short path, since a socket path is limited to about
// 100 bytes and t.TempDir can be longer.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "esc") //nolint:usetesting // t.TempDir can exceed the socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveSocket serves e's API on a socket at path until the test ends.
func serveSocket(t *testing.T, e *Escrow, path string) {
	t.Helper()
	ln, err := ListenSocket(t.Context(), path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e.Handler(), ConnContext: ConnContext, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
}

// socketGet requests path over the socket, with "Authorization: Bearer key" unless key is empty.
func socketGet(t *testing.T, sock, method, path, key string) (int, string) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://escrow"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

func TestSocketPeerAuth(t *testing.T) {
	t.Parallel()
	own := os.Geteuid()
	for _, c := range []struct {
		name    string
		allow   []int
		keyless bool
	}{
		{"own uid allowed", []int{own}, true},
		{"no uid allowed", []int{}, false},
		{"another uid allowed", []int{own + 1}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			e := New(Options{KeyHash: testHash(), AllowUIDs: c.allow, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
			marker := e.Replacer(Source{Server: "s", Tool: "t"}).Replace(redact.Finding{Kind: "password", Value: "Qwerty-12345"})
			handle := markerRE.FindStringSubmatch(marker)[2]
			sock := filepath.Join(shortDir(t), "escrow.sock")
			serveSocket(t, e, sock)

			// The client is the gate's own process: on Linux it needs the key even when its user
			// ID is allowed (see TestSocketProcessTree); macOS does not check the process tree.
			keyless := c.keyless && runtime.GOOS == "darwin"
			code, body := socketGet(t, sock, http.MethodGet, "/_escrow/"+handle, "")
			if keyless && (code != http.StatusOK || body != "Qwerty-12345") {
				t.Errorf("without a key = %d %q, want the value", code, body)
			}
			if !keyless && code != http.StatusUnauthorized {
				t.Errorf("without a key = %d, want 401", code)
			}
			if code, body := socketGet(t, sock, http.MethodGet, "/_escrow/"+handle, testKey); code != http.StatusOK || body != "Qwerty-12345" {
				t.Errorf("with the key = %d %q", code, body)
			}
			if !strings.Contains(logs.String(), `"remote":"unix:uid=`+strconv.Itoa(own)+`"`) {
				t.Errorf("access log lacks the peer:\n%s", logs.String())
			}
		})
	}
}

func TestListenSocket(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)

	// The parent directory is created 0700.
	path := filepath.Join(dir, "sub", "escrow.sock")
	ln, err := ListenSocket(t.Context(), path, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("parent = %v, %v; want 0700", fi, err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket = %v, %v; want a socket, 0660", fi, err)
	}
	// A socket someone listens on is not taken over.
	if _, err := ListenSocket(t.Context(), path, 0o600); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("a live socket: %v", err)
	}
	// Closing removes the file.
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("after close: %v", err)
	}

	// A stale socket left by a process that died is replaced.
	stale := filepath.Join(dir, "stale.sock")
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	_ = old.Close()
	ln, err = ListenSocket(t.Context(), stale, 0o600)
	if err != nil {
		t.Fatalf("a stale socket: %v", err)
	}
	_ = ln.Close()

	// Anything else at the path is left alone.
	file := filepath.Join(dir, "file.sock")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenSocket(t.Context(), file, 0o600); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("a regular file: %v", err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "x" {
		t.Errorf("the regular file was touched: %q, %v", data, err)
	}
}
