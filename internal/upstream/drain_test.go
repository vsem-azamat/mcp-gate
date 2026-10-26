package upstream

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

// rawConn is a client connection that sends requests by hand, to control which connection each
// request goes on.
type rawConn struct {
	net.Conn
	r *bufio.Reader
}

func dialRaw(t *testing.T, addr string) *rawConn {
	t.Helper()
	var d net.Dialer
	c, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawConn{Conn: c, r: bufio.NewReader(c)}
}

func (c *rawConn) send(t *testing.T, path string) {
	t.Helper()
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
}

// read reads a response and reports whether the server said it closes the connection.
func (c *rawConn) read(t *testing.T) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := http.ReadResponse(c.r, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status %d", res.StatusCode)
	}
	return res.Close
}

// TestDrain checks that Drain stops accepting but still answers requests on open connections,
// closing each after its response, a call that began before Drain included, and returns once
// no connection is left idle.
func TestDrain(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/slow", func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	})
	srv := NewServer("", mux, slog.New(slog.DiscardHandler))
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	addr := ln.Addr().String()

	idle := dialRaw(t, addr)
	idle.send(t, "/a")
	if idle.read(t) {
		t.Fatal("a response before Drain closes the connection")
	}
	busy := dialRaw(t, addr)
	busy.send(t, "/slow")
	<-started

	drained := make(chan time.Duration, 1)
	go func() {
		begun := time.Now()
		srv.Drain(t.Context(), 10*time.Second)
		drained <- time.Since(begun)
	}()
	// New connections are no longer accepted once the listener is closed.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var d net.Dialer
		c, err := d.DialContext(t.Context(), "tcp", addr)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener still accepts during Drain")
		}
		time.Sleep(10 * time.Millisecond)
	}

	idle.send(t, "/b")
	if !idle.read(t) {
		t.Error("a request on an idle connection during Drain kept the connection")
	}
	close(release)
	if !busy.read(t) {
		t.Error("a call that began before Drain kept its connection")
	}
	for _, c := range []*rawConn{idle, busy} {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.r.ReadByte(); !errors.Is(err, io.EOF) {
			t.Errorf("the connection was not closed: %v", err)
		}
	}
	select {
	case took := <-drained:
		if took > 5*time.Second {
			t.Errorf("Drain took %s with no connection left", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return once no connection was left")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("serve: %v", err)
	}
}

// TestDrainLinger checks that an idle connection holds Drain for at most its linger.
func TestDrainLinger(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), slog.New(slog.DiscardHandler))
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	c := dialRaw(t, ln.Addr().String())
	c.send(t, "/")
	c.read(t)
	begun := time.Now()
	srv.Drain(t.Context(), 200*time.Millisecond)
	if took := time.Since(begun); took < 200*time.Millisecond || took > 3*time.Second {
		t.Errorf("Drain with an idle connection took %s, want its linger", took)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("serve: %v", err)
	}
}
