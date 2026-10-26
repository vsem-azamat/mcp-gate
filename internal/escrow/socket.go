package escrow

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

// peerKey is the context key of a socket peer's credentials.
type peerKey struct{}

// sockPeer is the user of a unix socket peer; known is false when the system did not say.
// outsideGate is true only when the peer is known not to be the gate or one of its descendants.
type sockPeer struct {
	uid         int
	known       bool
	outsideGate bool
}

// ConnContext is an http.Server's ConnContext for the escrow socket: it records the peer's user
// ID, read from the kernel when the peer connected, in the context of the connection's
// requests, and whether the peer is outside the gate's process tree (see outsideGateTree).
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	p := sockPeer{}
	if uc, ok := c.(*net.UnixConn); ok {
		if uid, pid, err := peerCred(uc); err == nil {
			p = sockPeer{uid: uid, known: true, outsideGate: outsideGateTree(pid)}
		}
	}
	return context.WithValue(ctx, peerKey{}, p)
}

// socketPeer returns the socket peer of a request, and false for a request that did not come
// through the escrow socket.
func socketPeer(ctx context.Context) (sockPeer, bool) {
	p, ok := ctx.Value(peerKey{}).(sockPeer)
	return p, ok
}

// String is the peer's client address in logs and in the failed-auth limit.
func (p sockPeer) String() string {
	if !p.known {
		return "unix:uid=unknown"
	}
	return "unix:uid=" + strconv.Itoa(p.uid)
}

// ListenSocket listens on a unix socket at path with the given permission bits. A missing parent
// directory is created 0700; the directory must belong to root or the gate's user and be
// writable by nobody else (a sticky directory only when root's), since whoever can write it can
// replace the socket. A socket file already at path is removed when connecting to it is refused
// (a gate that died left it); anything else there, or a socket that may be in use, is an error.
// The socket is bound in a private directory, given its mode and then renamed into place, so it
// never has a wider mode. Closing the listener removes the file.
func ListenSocket(ctx context.Context, path string, mode fs.FileMode) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("escrow socket directory: %w", err)
	}
	if err := checkSocketDir(dir); err != nil {
		return nil, fmt.Errorf("escrow socket directory %s: %w", dir, err)
	}
	if err := removeStale(ctx, path); err != nil {
		return nil, err
	}
	private, err := os.MkdirTemp(dir, ".e")
	if err != nil {
		return nil, fmt.Errorf("escrow socket: %w", err)
	}
	defer func() { _ = os.RemoveAll(private) }()
	tmp := filepath.Join(private, "s")
	if len(tmp) > maxSocketPath {
		return nil, fmt.Errorf("escrow socket %s: the path is too long to bind it under a temporary name; shorten it", path)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("escrow socket: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("escrow socket %s: not a unix listener", path)
	}
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, mode); err != nil {
		_ = ul.Close()
		return nil, fmt.Errorf("escrow socket %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ul.Close()
		return nil, fmt.Errorf("escrow socket %s: %w", path, err)
	}
	return &socketListener{UnixListener: ul, path: path}, nil
}

// maxSocketPath is the longest unix socket path every supported system takes (sun_path is 104
// bytes on darwin, with the terminating NUL).
const maxSocketPath = 103

// socketListener removes its socket file when it is closed.
type socketListener struct {
	*net.UnixListener
	path string
	once sync.Once
}

func (l *socketListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() { _ = os.Remove(l.path) })
	return err
}

// checkSocketDir accepts a directory owned by root or the gate's user that neither its group
// nor others can write, or a sticky one owned by root.
func checkSocketDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("is not a directory")
	}
	owner := -1
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		owner = int(st.Uid)
	}
	if owner != 0 && owner != os.Geteuid() {
		return errors.New("is owned by another user; it must be root's or the gate's")
	}
	if fi.Mode().Perm()&0o022 != 0 && (fi.Mode()&fs.ModeSticky == 0 || owner != 0) {
		return errors.New("is writable by its group or others; only a sticky directory owned by root may be")
	}
	return nil
}

// removeStale removes a socket file at path that nothing listens on. Only a refused connection
// means nothing listens; a full backlog (EAGAIN) or a socket this user may not connect to
// (EACCES) may still be in use. Two gates started at the same moment on one path can still race
// here; one path serves one gate.
func removeStale(ctx context.Context, path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("escrow socket %s: %w", path, err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("escrow socket %s: is not a socket; not removing it", path)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("escrow socket %s: in use by another process", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("escrow socket %s: cannot tell whether it is in use; not removing it: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("escrow socket %s: removing the stale socket: %w", path, err)
	}
	return nil
}

// peerCred reads the user ID and process ID of the process at the other end of c; the process
// ID is 0 where the system does not report it.
func peerCred(c *net.UnixConn) (uid, pid int, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credErr error
	if err := raw.Control(func(fd uintptr) { uid, pid, credErr = fdPeerCred(int(fd)) }); err != nil {
		return 0, 0, err
	}
	return uid, pid, credErr
}
