package escrow

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// The environment variables that hold the hex SHA-256 of the API key. The key itself never
// reaches the gate.
const (
	KeyHashEnv = "MCP_GATE_ESCROW_KEY_SHA256"
	// LegacyKeyHashEnv is the deprecated name of KeyHashEnv, which mcp-proxy read; it is still
	// read, with a warning at start.
	LegacyKeyHashEnv = "MCP_HUB_ESCROW_KEY_SHA256"
)

// The names of the config keys that hold the key hash, as sources of a Key.
const (
	KeyHashKey     = "escrow.keyHash"
	KeyHashFileKey = "escrow.keyHashFile"
)

// maxKeyHashFileBytes bounds what is read from a key hash file: a hash, a line break and some
// space.
const maxKeyHashFileBytes = 1 << 10

// KeyConfig is the key hash as the config gives it: at most one of the two is set.
type KeyConfig struct {
	// Hash is the hex SHA-256 itself.
	Hash string
	// HashFile is the path of a file that holds it.
	HashFile string
}

// Key is the resolved key hash and where it came from.
type Key struct {
	Hash [sha256.Size]byte
	// Source is KeyHashKey, KeyHashFileKey, KeyHashEnv or LegacyKeyHashEnv.
	Source string
	// Deprecated reports that LegacyKeyHashEnv is set, whether or not it is the source.
	Deprecated bool
}

// ResolveKey finds the key hash, or returns nil when the escrow is off. The sources, in order of
// precedence, are the config, KeyHashEnv and LegacyKeyHashEnv; a variable that holds only space
// is not set. Every source that is set must hold a hex SHA-256, and they must all hold the same
// one. Errors name the sources, never a value.
func ResolveKey(c KeyConfig, lookup func(string) (string, bool)) (*Key, error) {
	type found struct {
		source string
		hash   [sha256.Size]byte
	}
	var all []found
	switch {
	case c.Hash != "":
		h, err := ParseKeyHash(c.Hash)
		if err != nil {
			return nil, fmt.Errorf("%s %w", KeyHashKey, err)
		}
		all = append(all, found{KeyHashKey, h})
	case c.HashFile != "":
		h, err := readKeyHashFile(c.HashFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", KeyHashFileKey, err)
		}
		all = append(all, found{KeyHashFileKey, h})
	}
	var deprecated bool
	for _, name := range []string{KeyHashEnv, LegacyKeyHashEnv} {
		v, _ := lookup(name)
		if strings.TrimSpace(v) == "" {
			continue
		}
		deprecated = deprecated || name == LegacyKeyHashEnv
		h, err := ParseKeyHash(v)
		if err != nil {
			return nil, fmt.Errorf("%s %w", name, err)
		}
		all = append(all, found{name, h})
	}
	if len(all) == 0 {
		return nil, nil
	}
	for _, f := range all[1:] {
		if f.hash != all[0].hash {
			return nil, fmt.Errorf("%s and %s hold different hashes; set the key hash in one place", all[0].source, f.source)
		}
	}
	return &Key{Hash: all[0].hash, Source: all[0].source, Deprecated: deprecated}, nil
}

// ParseKeyHash decodes a hex SHA-256: 64 hex digits in either case, surrounding space ignored.
// The error never quotes the value.
func ParseKeyHash(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	decoded, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || len(decoded) != sha256.Size {
		return out, errors.New("is not a hex SHA-256")
	}
	copy(out[:], decoded)
	return out, nil
}

// readKeyHashFile reads the key hash from a file, such as a systemd credential or a mounted
// secret. Symlinks are followed. The file must be a regular file of at most 1 KiB, owned by root
// or by the gate's user and writable by neither its group nor others, since whoever can write it
// chooses the key; a gate running as root accepts any owner. Errors name neither the path nor the
// content.
func readKeyHashFile(path string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	// O_NONBLOCK: a FIFO at the path must not hold the start; it fails the regular-file check.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // the path is the operator's own config
	if err != nil {
		return zero, fmt.Errorf("cannot read the file: %w", pathless(err))
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return zero, fmt.Errorf("cannot read the file: %w", pathless(err))
	}
	if !info.Mode().IsRegular() {
		return zero, errors.New("is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return zero, errors.New("is writable by its group or others; make it 0400 or 0600")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && !ownerOK(st.Uid, uint32(os.Geteuid())) { //nolint:gosec // a user ID fits 32 bits
		return zero, errors.New("is owned by another user; it must be owned by root or by the gate's user")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyHashFileBytes+1))
	if err != nil {
		return zero, fmt.Errorf("cannot read the file: %w", pathless(err))
	}
	defer clear(data)
	if len(data) > maxKeyHashFileBytes {
		return zero, errors.New("is not a hex SHA-256: the file is too long")
	}
	h, err := ParseKeyHash(string(data))
	if err != nil {
		return zero, fmt.Errorf("the file %w", err)
	}
	return h, nil
}

// ownerOK reports whether a key hash file owned by owner may be trusted by a process running as
// euid: one owned by root or by euid. Root trusts any owner, so that `sudo mcp-gate check` reads a
// credential owned by the service's user.
func ownerOK(owner, euid uint32) bool {
	return owner == 0 || owner == euid || euid == 0
}

// pathless drops the path from a file error.
func pathless(err error) error {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		return pe.Err
	}
	return err
}
