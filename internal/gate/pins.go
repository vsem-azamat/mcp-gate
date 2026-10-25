package gate

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// PinsFile is the file in the state directory that keeps learned protocol pins.
const PinsFile = "pins.json"

// pinStore keeps the protocol versions servers were pinned to automatically, so that a restart
// of the gate does not wait for the discover sub-deadline again. A nil store keeps nothing.
type pinStore struct {
	path string
	mu   sync.Mutex
	pins map[string]string
}

type pinsDoc struct {
	Version int               `json:"version"`
	Pins    map[string]string `json:"pins"`
}

// loadPins reads the pins in dir; an empty dir keeps none. A missing file is an empty store.
func loadPins(dir string) (*pinStore, error) {
	if dir == "" {
		return nil, nil
	}
	s := &pinStore{path: filepath.Join(dir, PinsFile), pins: map[string]string{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var doc pinsDoc
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != 1 {
		return s, errors.New(s.path + ": not a pins file of version 1")
	}
	for name, v := range doc.Pins {
		if slices.Contains(mcp.SupportedProtocolVersions(), v) {
			s.pins[name] = v
		}
	}
	return s, nil
}

func (s *pinStore) get(name string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pins[name]
}

// set records a pin and writes the file: to a temporary file in the same directory, synced, then
// renamed over the old one.
func (s *pinStore) set(name, version string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[name] = version
	data, err := json.MarshalIndent(pinsDoc{Version: 1, Pins: s.pins}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), PinsFile+".*")
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
	return os.Rename(tmp.Name(), s.path)
}
