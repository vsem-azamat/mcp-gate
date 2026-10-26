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

// The deadline bounds each write, not the response: a client that reads slowly but steadily
// gets the whole answer, and the next request on the connection is not failed by a deadline
// the previous one left.
func TestBoundWritesSlowReaderAndKeepAlive(t *testing.T) {
	t.Parallel()
	const timeout = 300 * time.Millisecond
	body := strings.Repeat("x", 1<<20)
	srv := httptest.NewServer(BoundWrites(timeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = io.WriteString(w, body)
			return
		}
		time.Sleep(2 * timeout) // a call that answers after the previous request's deadline
		_, _ = io.WriteString(w, "ok")
	})))
	t.Cleanup(srv.Close)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	br := bufio.NewReaderSize(conn, 4<<10)
	if _, err := io.WriteString(conn, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 16<<10)
	n := 0
	for {
		m, err := resp.Body.Read(buf)
		n += m
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_ = resp.Body.Close()
	if n != len(body) {
		t.Fatalf("read %d of %d bytes in %v", n, len(body), time.Since(start))
	}
	time.Sleep(2 * timeout)
	if _, err := io.WriteString(conn, "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
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
