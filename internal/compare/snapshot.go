package compare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SnapshotVersion is the format version of the snapshots this build reads and writes.
const SnapshotVersion = 1

// Snapshot is a set of catalogs saved to a file, read back as a source.
type Snapshot struct {
	Version int                `json:"version"`
	Servers map[string]Catalog `json:"servers"`
}

// ReadSnapshot reads a snapshot file. Unknown fields, trailing data and other versions are errors.
func ReadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's command-line argument
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: trailing data after the snapshot", path)
	}
	if s.Version != SnapshotVersion {
		return nil, fmt.Errorf("%s: snapshot version %d, want %d", path, s.Version, SnapshotVersion)
	}
	for name, cat := range s.Servers {
		cat.sort()
		s.Servers[name] = cat
	}
	return &s, nil
}

// Catalog returns the saved catalog of a server.
func (s *Snapshot) Catalog(_ context.Context, server string) (Catalog, error) {
	cat, ok := s.Servers[server]
	if !ok {
		return Catalog{}, fmt.Errorf("server %q is not in the snapshot", server)
	}
	return cat, nil
}

// ServerNames returns the names of the servers in the snapshot, sorted.
func (s *Snapshot) ServerNames() []string { return slices.Sorted(maps.Keys(s.Servers)) }

// WriteSnapshot writes the catalogs to path as a snapshot, replacing the file atomically.
func WriteSnapshot(path string, servers map[string]Catalog) (err error) {
	s := Snapshot{Version: SnapshotVersion, Servers: make(map[string]Catalog, len(servers))}
	for name, cat := range servers {
		cat.sort()
		s.Servers[name] = cat.nonNil()
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(0o644); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// nonNil returns the catalog with empty lists in place of nil ones, so they encode as [].
func (c Catalog) nonNil() Catalog {
	if c.Tools == nil {
		c.Tools = []*mcp.Tool{}
	}
	if c.Prompts == nil {
		c.Prompts = []*mcp.Prompt{}
	}
	if c.Resources == nil {
		c.Resources = []*mcp.Resource{}
	}
	if c.ResourceTemplates == nil {
		c.ResourceTemplates = []*mcp.ResourceTemplate{}
	}
	return c
}
