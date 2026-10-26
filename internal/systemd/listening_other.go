//go:build !linux

package systemd

// listening reports whether fd is a socket that listens. Only Linux tells it; elsewhere
// net.FileListener takes a connected socket and the first accept fails.
func listening(int) bool { return true }
