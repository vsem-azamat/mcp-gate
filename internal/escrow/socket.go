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
)

// peerKey is the context key of a socket peer's credentials.
type peerKey struct{}

// socketPeer is the user of a unix socket peer; known is false when the system did not say.
type sockPeer struct {
	uid   int
	known bool
}

// ConnContext is an http.Server's ConnContext for the escrow socket: it records the peer's user
// ID, read from the kernel, in the context of the connection's requests.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	p := sockPeer{}
	if uc, ok := c.(*net.UnixConn); ok {
		if uid, err := peerUID(uc); err == nil {
			p = sockPeer{uid: uid, known: true}
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
// directory is created 0700. A socket file already at path is removed when nothing listens on it
// (a gate that died left it); anything else there, or a socket in use, is an error.
func ListenSocket(ctx context.Context, path string, mode fs.FileMode) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("escrow socket directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("escrow socket %s: is not a socket; not removing it", path)
		}
		var d net.Dialer
		if c, err := d.DialContext(ctx, "unix", path); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("escrow socket %s: in use by another process", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("escrow socket %s: removing the stale socket: %w", path, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("escrow socket %s: %w", path, err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("escrow socket: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("escrow socket %s: not a unix listener", path)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ul.Close()
		return nil, fmt.Errorf("escrow socket %s: %w", path, err)
	}
	return ul, nil
}

// peerUID reads the user ID of the process at the other end of c.
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var credErr error
	if err := raw.Control(func(fd uintptr) { uid, credErr = fdPeerUID(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, credErr
}
