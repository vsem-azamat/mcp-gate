package gate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

func TestPinsPrune(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := &config.Server{Transport: `{"command":"/bin/a"}`}
	b := &config.Server{Transport: `{"url":"https://b.example.com/mcp"}`}
	s, err := loadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, srv := range map[string]*config.Server{"a": a, "b": b, "gone": a} {
		if err := s.set(name, "2025-11-25", transportHash(srv)); err != nil {
			t.Fatal(err)
		}
	}
	moved := &config.Server{Transport: `{"url":"https://b2.example.com/mcp"}`}
	if err := s.prune(&config.Config{Servers: map[string]*config.Server{"a": a, "b": moved}}); err != nil {
		t.Fatal(err)
	}
	s, err = loadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.get("a", transportHash(a)) != "2025-11-25" || len(s.pins) != 1 {
		t.Errorf("pins after pruning = %+v, want only a", s.pins)
	}
	if s.get("a", transportHash(b)) != "" {
		t.Error("a pin applies to another transport")
	}
}

func TestPinsFirstVersionIsEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PinsFile), []byte(`{"version": 1, "pins": {"a": "2025-11-25"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadPins(dir)
	if err != nil || len(s.pins) != 0 {
		t.Errorf("loadPins = %+v, %v; want an empty store", s.pins, err)
	}
}
