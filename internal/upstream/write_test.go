package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A client that sends a request and never reads the answer must not hold the handler: a write
// that makes no progress fails and the request's context ends.
func TestBoundWritesStalledReader(t *testing.T) {
	t.Parallel()
	type outcome struct {
		err    error
		ctxErr error
	}
	done := make(chan outcome, 1)
	chunk := make([]byte, 256<<10)
	srv := httptest.NewServer(BoundWrites(200*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		for err == nil {
			_, err = w.Write(chunk) // until the socket buffers are full and a write stalls
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		done <- outcome{err, r.Context().Err()}
	})))
	t.Cleanup(srv.Close)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-done:
		if o.err == nil || o.ctxErr == nil {
			t.Errorf("write error %v, context %v; want both", o.err, o.ctxErr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the handler is still writing to a client that does not read")
	}
}

// smallBuffers is a listener whose connections have small send buffers, so that a large
// response cannot sit in the kernel and each write waits for the reader.
type smallBuffers struct{ net.Listener }

func (l smallBuffers) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(128 << 10)
	}
	return c, err
}

// serveSmall serves h with small socket buffers and returns a client connection whose receive
// buffer is small too.
func serveSmall(t *testing.T, h http.Handler) (net.Conn, *bufio.Reader) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = smallBuffers{srv.Listener}
	srv.Start()
	t.Cleanup(srv.Close)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(128 << 10)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, bufio.NewReaderSize(conn, 64<<10)
}

// The deadline bounds each write of at most 64 KiB, not the response: a client that reads
// slowly but steadily gets the whole answer, written in one Write that takes far longer than the
// timeout, and the next request on the connection is not failed by a deadline the previous one
// left.
func TestBoundWritesSlowReaderAndKeepAlive(t *testing.T) {
	t.Parallel()
	const timeout = 500 * time.Millisecond
	body := strings.Repeat("x", 4<<20)
	conn, br := serveSmall(t, BoundWrites(timeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = io.WriteString(w, body) // one Write; BoundWrites cuts it
			return
		}
		_, _ = io.WriteString(w, "ok")
	})))
	if _, err := io.WriteString(conn, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 64<<10)
	n := 0
	for {
		// 64 KiB every 25 ms: each piece well within the timeout, the whole body not.
		m, err := io.ReadFull(resp.Body, buf)
		n += m
		if err != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = resp.Body.Close()
	took := time.Since(start)
	if n != len(body) {
		t.Fatalf("read %d of %d bytes in %v", n, len(body), took)
	}
	if took < timeout {
		t.Errorf("the body took %v, which does not test a response longer than the timeout", took)
	}
	time.Sleep(2 * timeout)
	if _, err := io.WriteString(conn, "GET /small HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the next request on the connection: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(got) != "ok" {
		t.Errorf("the next request = %q, %v", got, err)
	}
}

// A stream that is idle for longer than the timeout between two writes, as an event stream is,
// is not cut: the deadline is set before each write, not kept between them.
func TestBoundWritesIdleStream(t *testing.T) {
	t.Parallel()
	const timeout = 200 * time.Millisecond
	conn, br := serveSmall(t, BoundWrites(timeout, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		_ = http.NewResponseController(w).Flush()
		time.Sleep(3 * timeout)
		_, _ = io.WriteString(w, "second\n")
	})))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(got) != "first\nsecond\n" {
		t.Errorf("stream = %q, %v", got, err)
	}
}

// BoundWrites keeps flushing reachable, which streaming answers need.
func TestBoundWritesFlushes(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	BoundWrites(time.Second, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "a")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if !rec.Flushed || rec.Body.String() != "a" {
		t.Errorf("flushed %v, body %q", rec.Flushed, rec.Body)
	}
}
