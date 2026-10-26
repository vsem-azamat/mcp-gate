package systemd

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
}

// passed returns a duplicate descriptor of a listener's socket, as systemd would pass it.
func passed(t *testing.T, network, addr string) (int, string) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	filer, ok := ln.(interface{ File() (*os.File, error) })
	if !ok {
		t.Fatalf("listener is %T", ln)
	}
	f, err := filer.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd, ln.Addr().String()
}

func TestListener(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	fd, addr := passed(t, "tcp", "127.0.0.1:0")
	ln, err := listener(env(map[string]string{ListenFDsEnv: "1", ListenPIDEnv: pid}), os.Getpid(), fd)
	if err != nil || ln == nil {
		t.Fatalf("listener = %v, %v", ln, err)
	}
	defer ln.Close()
	if ln.Addr().String() != addr {
		t.Errorf("addr = %s, want %s", ln.Addr(), addr)
	}
	// The passed descriptor is closed; the listener holds a close-on-exec duplicate.
	if _, err := syscall.Dup(fd); err == nil {
		t.Error("the passed descriptor is still open")
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	var d net.Dialer
	c, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestListenerNone(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	for name, vars := range map[string]map[string]string{
		"unset":         {},
		"other process": {ListenFDsEnv: "1", ListenPIDEnv: "1"},
		"no pid":        {ListenFDsEnv: "1"},
		"zero":          {ListenFDsEnv: "0", ListenPIDEnv: pid},
	} {
		ln, err := listener(env(vars), os.Getpid(), 1<<20)
		if ln != nil || err != nil {
			t.Errorf("%s: %v, %v", name, ln, err)
		}
	}
}

func TestListenerErrors(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	unixFD, _ := passed(t, "unix", filepath.Join(t.TempDir(), "s"))
	f, err := os.CreateTemp(t.TempDir(), "file")
	if err != nil {
		t.Fatal(err)
	}
	fileFD, err := syscall.Dup(int(f.Fd()))
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	// A connected TCP socket, as Accept=yes would pass.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("conn is %T", conn)
	}
	connFile, err := tcpConn.File()
	if err != nil {
		t.Fatal(err)
	}
	defer connFile.Close()
	for _, c := range []struct {
		name, fds string
		fd        int
		want      string
	}{
		{"connected", "1", int(connFile.Fd()), "not a listening socket"},
		{"garbage", "x", 1 << 20, "not a number"},
		{"two", "2", 1 << 20, "passed 2 sockets"},
		{"unix", "1", unixFD, "not TCP"},
		{"file", "1", fileFD, "not a listening socket"},
	} {
		if c.name == "connected" && runtime.GOOS != "linux" {
			continue // only Linux tells a listening socket from a connected one
		}
		ln, err := listener(env(map[string]string{ListenFDsEnv: c.fds, ListenPIDEnv: pid}), os.Getpid(), c.fd)
		if ln != nil || err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, %v; want an error with %q", c.name, ln, err, c.want)
		}
	}
}

func TestNotify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n, err := NewNotifier(env(map[string]string{NotifySocketEnv: path}))
	if err != nil || !n.Enabled() {
		t.Fatalf("NewNotifier = %v, %v", n, err)
	}
	if err := n.Notify(Ready); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	k, err := conn.Read(buf)
	if err != nil || string(buf[:k]) != Ready {
		t.Errorf("read %q, %v", buf[:k], err)
	}

	off, err := NewNotifier(env(nil))
	if err != nil || off.Enabled() || off.Notify(Ready) != nil {
		t.Errorf("without NOTIFY_SOCKET: %v, %v", off, err)
	}
	if _, err := NewNotifier(env(map[string]string{NotifySocketEnv: "relative"})); err == nil {
		t.Error("a relative socket path was taken")
	}
	abstract, err := NewNotifier(env(map[string]string{NotifySocketEnv: "@mcp-gate-test"}))
	if err != nil || abstract.addr.Name != "\x00mcp-gate-test" {
		t.Errorf("abstract socket: %v, %v", abstract, err)
	}
}
