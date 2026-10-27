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
	a := &config.Server{Stdio: &config.Stdio{Command: "/bin/a", Args: []string{"--stdio"}}}
	b := &config.Server{HTTP: &config.HTTP{URL: "https://b.example.com/mcp"}}
	s, err := loadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, srv := range map[string]*config.Server{"a": a, "b": b, "gone": a} {
		if err := s.set(name, "2025-11-25", transportHash(srv)); err != nil {
			t.Fatal(err)
		}
	}
	moved := &config.Server{HTTP: &config.HTTP{URL: "https://b2.example.com/mcp"}}
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

func TestPinsTransportHash(t *testing.T) {
	t.Parallel()
	base := func() *config.Server {
		return &config.Server{Stdio: &config.Stdio{Command: "/bin/a", Args: []string{"x"}, Env: map[string]string{"K": "v"}}}
	}
	h := transportHash(base())
	env := base()
	env.Stdio.Env["K"] = "other"
	if transportHash(env) != h {
		t.Error("the environment changes the transport hash")
	}
	for _, change := range []func(*config.Server){
		func(s *config.Server) { s.Stdio.Command = "/bin/b" },
		func(s *config.Server) { s.Stdio.Args = []string{"y"} },
		func(s *config.Server) { s.Stdio.Cwd = "/srv" },
	} {
		s := base()
		change(s)
		if transportHash(s) == h {
			t.Errorf("a change to %+v keeps the transport hash", s.Stdio)
		}
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
