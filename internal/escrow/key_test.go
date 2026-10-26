package escrow

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func hashHex(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func lookupOf(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func writeHashFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "escrow-key-sha256")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveKey(t *testing.T) {
	t.Parallel()
	a, b := hashHex("key-a"), hashHex("key-b")
	ha := sha256.Sum256([]byte("key-a"))
	file := writeHashFile(t, a+"\n", 0o400)
	cases := []struct {
		name       string
		cfg        KeyConfig
		env        map[string]string
		wantSource string // "" means off
		deprecated bool
	}{
		{name: "nothing", cfg: KeyConfig{}, env: map[string]string{KeyHashEnv: "  "}},
		{name: "legacy variable alone", env: map[string]string{LegacyKeyHashEnv: a}, wantSource: LegacyKeyHashEnv, deprecated: true},
		{name: "new variable", env: map[string]string{KeyHashEnv: a}, wantSource: KeyHashEnv},
		{name: "both variables, same hash", env: map[string]string{KeyHashEnv: a, LegacyKeyHashEnv: strings.ToUpper(a)}, wantSource: KeyHashEnv, deprecated: true},
		{name: "config wins", cfg: KeyConfig{Hash: a}, env: map[string]string{KeyHashEnv: a}, wantSource: "escrow.keyHash"},
		{name: "config file", cfg: KeyConfig{HashFile: file}, env: map[string]string{LegacyKeyHashEnv: a}, wantSource: "escrow.keyHashFile", deprecated: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			key, err := ResolveKey(c.cfg, lookupOf(c.env))
			if err != nil {
				t.Fatal(err)
			}
			if c.wantSource == "" {
				if key != nil {
					t.Errorf("key = %+v, want off", key)
				}
				return
			}
			if key == nil || key.Source != c.wantSource || key.Hash != ha || key.Deprecated != c.deprecated {
				t.Errorf("key = %+v, want source %s, deprecated %v", key, c.wantSource, c.deprecated)
			}
		})
	}
	for _, c := range []struct {
		name string
		cfg  KeyConfig
		env  map[string]string
		want string
	}{
		{"variables differ", KeyConfig{}, map[string]string{KeyHashEnv: a, LegacyKeyHashEnv: b}, "MCP_GATE_ESCROW_KEY_SHA256 and MCP_HUB_ESCROW_KEY_SHA256 hold different hashes"},
		{"config and variable differ", KeyConfig{Hash: a}, map[string]string{KeyHashEnv: b}, "escrow.keyHash and MCP_GATE_ESCROW_KEY_SHA256 hold different hashes"},
		{"invalid legacy variable", KeyConfig{Hash: a}, map[string]string{LegacyKeyHashEnv: "zz-not-a-hash"}, "MCP_HUB_ESCROW_KEY_SHA256 is not a hex SHA-256"},
		{"invalid variable", KeyConfig{}, map[string]string{KeyHashEnv: "zz-not-a-hash"}, "MCP_GATE_ESCROW_KEY_SHA256 is not a hex SHA-256"},
		{"missing file", KeyConfig{HashFile: filepath.Join(t.TempDir(), "absent")}, nil, "escrow.keyHashFile: cannot read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := ResolveKey(c.cfg, lookupOf(c.env))
			if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), a) || strings.Contains(err.Error(), "zz-not") {
				t.Errorf("error = %v, want %q without a value", err, c.want)
			}
		})
	}
}

func TestReadKeyHashFile(t *testing.T) {
	t.Parallel()
	a := hashHex("key-a")
	want := sha256.Sum256([]byte("key-a"))
	for _, mode := range []os.FileMode{0o400, 0o600, 0o644} {
		path := writeHashFile(t, " "+strings.ToUpper(a)+"\r\n", mode)
		if got, err := readKeyHashFile(path); err != nil || got != want {
			t.Errorf("mode %o: %x, %v", mode, got, err)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(writeHashFile(t, a, 0o400), link); err != nil {
		t.Fatal(err)
	}
	if got, err := readKeyHashFile(link); err != nil || got != want {
		t.Errorf("through a symlink: %x, %v", got, err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path string
		want string
	}{
		"group-writable":  {writeHashFile(t, a, 0o620), "writable by its group or others"},
		"world-writable":  {writeHashFile(t, a, 0o602), "writable by its group or others"},
		"not a hash":      {writeHashFile(t, "zz-not-a-hash", 0o400), "is not a hex SHA-256"},
		"a directory":     {t.TempDir(), "is not a regular file"},
		"a FIFO":          {fifo, "is not a regular file"},
		"far too long":    {writeHashFile(t, strings.Repeat(a, 100), 0o400), "is not a hex SHA-256"},
		"two hashes":      {writeHashFile(t, a+"\n"+a, 0o400), "is not a hex SHA-256"},
		"does not exist":  {filepath.Join(t.TempDir(), "absent"), "cannot read the file"},
		"empty":           {writeHashFile(t, "", 0o400), "is not a hex SHA-256"},
		"only whitespace": {writeHashFile(t, " \n", 0o400), "is not a hex SHA-256"},
	} {
		_, err := readKeyHashFile(c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "zz-not") || strings.Contains(err.Error(), c.path) {
			t.Errorf("%s: %v, want %q without the content or the path", name, err, c.want)
		}
	}
}

func TestKeyHashFileOwner(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		owner, euid uint32
		ok          bool
	}{
		{0, 1000, true}, {1000, 1000, true}, {1001, 1000, false}, {1001, 0, true},
	} {
		if got := ownerOK(c.owner, c.euid); got != c.ok {
			t.Errorf("ownerOK(%d, %d) = %v, want %v", c.owner, c.euid, got, c.ok)
		}
	}
}
