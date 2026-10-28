package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// PinsFile is the file in the state directory that keeps learned protocol pins.
const PinsFile = "pins.json"

// pinsVersion is the version of the pins file this build writes and reads.
const pinsVersion = 2

// pinStore keeps the protocol versions servers were pinned to automatically, so that a restart
// of the gate does not wait for the discover sub-deadline again. A pin holds for the transport
// it was learned on (see transportHash). A nil store keeps nothing.
type pinStore struct {
	path string
	mu   sync.Mutex
	pins map[string]pin
}

// pin is a learned protocol version and the transport it was learned on.
type pin struct {
	Version   string `json:"version"`
	Transport string `json:"transport"`
}

type pinsDoc struct {
	Version int            `json:"version"`
	Pins    map[string]pin `json:"pins"`
}

// loadPins reads the pins in dir; an empty dir keeps none. A missing file, or one of the first
// version, which does not record transports, is an empty store.
func loadPins(dir string) (*pinStore, error) {
	if dir == "" {
		return nil, nil
	}
	s := &pinStore{path: filepath.Join(dir, PinsFile), pins: map[string]pin{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err == nil && head.Version == 1 {
		return s, nil
	}
	var doc pinsDoc
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != pinsVersion {
		return s, errors.New(s.path + ": not a pins file of version 2")
	}
	for name, p := range doc.Pins {
		if slices.Contains(mcp.SupportedProtocolVersions(), p.Version) && p.Transport != "" {
			s.pins[name] = p
		}
	}
	return s, nil
}

// transportHash identifies what a server's pin was learned on: the SHA-256 of its command,
// arguments and working directory, or of its URL, as written in the config (config.Server's
// Transport), so that the file holds nothing derived from the values of variables.
func transportHash(s *config.Server) string {
	sum := sha256.Sum256([]byte(s.Transport))
	return hex.EncodeToString(sum[:])
}

// get returns the pin of a server, if it was learned on the same transport.
func (s *pinStore) get(name, transport string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.pins[name]; p.Transport == transport {
		return p.Version
	}
	return ""
}

// set records a pin and writes the file.
func (s *pinStore) set(name, version, transport string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[name] = pin{Version: version, Transport: transport}
	return s.write()
}

// prune drops the pins of servers that cfg does not have and of servers whose transport
// changed, and writes the file when it dropped any.
func (s *pinStore) prune(cfg *config.Config) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.pins)
	for name, p := range s.pins {
		if srv := cfg.Servers[name]; srv == nil || transportHash(srv) != p.Transport {
			delete(s.pins, name)
		}
	}
	if len(s.pins) == n {
		return nil
	}
	return s.write()
}

// write writes the file: to a temporary file in the same directory, synced, renamed over the
// old one, and the directory synced, so that the rename lasts a crash. The caller holds mu.
func (s *pinStore) write() error {
	data, err := json.MarshalIndent(pinsDoc{Version: pinsVersion, Pins: s.pins}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, PinsFile+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir flushes a directory's entries to disk. A system that cannot sync a directory
// (EINVAL, ENOTSUP) is not an error.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the gate's own state directory
	if err != nil {
		return err
	}
	err = d.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		err = nil
	}
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
