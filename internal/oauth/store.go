package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// GrantVersion is the version of the grant file format this build reads and writes.
const GrantVersion = 1

// maxGrantBytes bounds a grant file.
const maxGrantBytes = 1 << 20

// Grant is what mcp-gate auth login obtains for one server: the authorization server it came
// from, the client, and the tokens. It is stored as JSON, one file per server.
type Grant struct {
	Version int `json:"version"`
	// ServerURL is the server's URL in the config at login; the grant is used only for it.
	ServerURL string `json:"serverURL"`
	// Resource is the resource indicator (RFC 8707) sent in authorization and token requests.
	Resource              string `json:"resource"`
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	ClientID              string `json:"clientID"`
	// ClientSecret is the secret of a dynamically registered client; a configured client's
	// secret stays in the config.
	ClientSecret string `json:"clientSecret,omitempty"`
	// Registered reports that the client was registered dynamically at login.
	Registered bool `json:"registered"`
	// AuthStyle is how the client authenticates to the token endpoint: AuthInHeader or
	// AuthInParams.
	AuthStyle   string   `json:"authStyle"`
	RedirectURL string   `json:"redirectURL"`
	Scopes      []string `json:"scopes,omitempty"`

	AccessToken  string `json:"accessToken"`
	TokenType    string `json:"tokenType"`
	RefreshToken string `json:"refreshToken,omitempty"`
	// Expiry is when the access token expires; zero when the server did not say.
	Expiry      time.Time `json:"expiry,omitzero"`
	ObtainedAt  time.Time `json:"obtainedAt"`
	RefreshedAt time.Time `json:"refreshedAt,omitzero"`
}

// Token endpoint authentication styles.
const (
	AuthInHeader = "header" // HTTP Basic, client_secret_basic
	AuthInParams = "params" // in the form body, client_secret_post or none
)

// Mismatch says why the grant cannot be used for a server with this URL and configured client
// ID (empty for a dynamically registered client); empty when it can.
func (g *Grant) Mismatch(serverURL, clientID string) string {
	switch {
	case g.ServerURL != serverURL:
		return "the grant is for another server URL"
	case clientID != "" && g.ClientID != clientID, clientID == "" && !g.Registered:
		return "the grant is for another OAuth client"
	}
	return ""
}

func (g *Grant) check() error {
	switch {
	case g.Version != GrantVersion:
		return fmt.Errorf("unknown grant file version %d", g.Version)
	case g.ServerURL == "" || g.TokenEndpoint == "" || g.ClientID == "" || g.AccessToken == "":
		return errors.New("the grant file is incomplete")
	case g.AuthStyle != AuthInHeader && g.AuthStyle != AuthInParams:
		return errors.New("the grant file has an unknown authStyle")
	}
	return nil
}

// lockPoll is how often Lock tries a lock another process holds.
const lockPoll = 20 * time.Millisecond

// Store keeps grants on disk: <dir>/<server>.json, written atomically, readable by the owner
// only. Server names are config server names, which are safe file names.
type Store struct {
	dir string
}

// NewStore returns the store under a state directory, in its oauth subdirectory; nil when
// stateDir is empty.
func NewStore(stateDir string) *Store {
	if stateDir == "" {
		return nil
	}
	return &Store{dir: filepath.Join(stateDir, "oauth")}
}

// Dir is the directory the grants are kept in.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(name string) string { return filepath.Join(s.dir, name+".json") }

// stamp identifies one version of a grant file; the zero stamp is no file.
type stamp struct{ fi os.FileInfo }

func statStamp(path string) stamp {
	fi, err := os.Lstat(path)
	if err != nil {
		return stamp{}
	}
	return stamp{fi}
}

// same reports whether two stamps are of the same file version: a save renames a new file over
// the old one, so the file changes identity.
func (a stamp) same(b stamp) bool {
	if a.fi == nil || b.fi == nil {
		return a.fi == nil && b.fi == nil
	}
	return os.SameFile(a.fi, b.fi) && a.fi.Size() == b.fi.Size() && a.fi.ModTime().Equal(b.fi.ModTime())
}

// bare drops the path from a file system error; the rest says what failed.
func bare(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// Load reads a server's grant; it returns nil and no error when there is none. A file that is
// not a regular file, is a symbolic link, or is readable by others is refused.
func (s *Store) Load(name string) (*Grant, error) {
	g, _, err := s.load(name)
	return g, err
}

func (s *Store) load(name string) (*Grant, stamp, error) {
	path := s.path(name)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the store directory and a config server name, which is a safe file name
	if errors.Is(err, os.ErrNotExist) {
		return nil, stamp{}, nil
	}
	if err != nil {
		return nil, stamp{}, fmt.Errorf("cannot open the grant file: %w", bare(err))
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, stamp{}, fmt.Errorf("cannot read the grant file: %w", bare(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, stamp{}, errors.New("the grant file is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, stamp{}, errors.New("the grant file is readable or writable by others; restrict it to 0600 or log in again")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxGrantBytes+1))
	if err != nil {
		return nil, stamp{}, fmt.Errorf("cannot read the grant file: %w", bare(err))
	}
	if len(data) > maxGrantBytes {
		return nil, stamp{}, errors.New("the grant file is too large")
	}
	st := stamp{fi}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var g Grant
	if err := dec.Decode(&g); err != nil {
		return nil, st, errors.New("the grant file is not valid")
	}
	if err := g.check(); err != nil {
		return nil, st, err
	}
	return &g, st, nil
}

// Save writes a server's grant: to a temporary file in the same directory, synced, renamed over
// the old one, and the directory synced. The directory is created 0700 and the file is 0600.
func (s *Store) Save(name string, g *Grant) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(g, "", "  ") //nolint:gosec // the grant file is where the secrets are kept, 0600
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.dir, "."+name+".json.tmp-*")
	if err != nil {
		return fmt.Errorf("cannot write the grant file: %w", bare(err))
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmp != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("cannot write the grant file: %w", bare(err))
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("cannot write the grant file: %w", bare(err))
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("cannot write the grant file: %w", bare(err))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write the grant file: %w", bare(err))
	}
	if err := os.Rename(tmpPath, s.path(name)); err != nil {
		_ = os.Remove(tmpPath)
		tmp = nil
		return fmt.Errorf("cannot write the grant file: %w", bare(err))
	}
	tmp = nil
	return s.syncDir()
}

// Delete removes a server's grant. It reports whether there was one; with an error, true means
// the file is removed but the directory could not be synced.
func (s *Store) Delete(name string) (bool, error) {
	err := os.Remove(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot remove the grant file: %w", bare(err))
	}
	return true, s.syncDir()
}

// Lock takes the server's lock file, which serialises refreshes and logins between processes
// (the gate, check -connect, auth login). The returned function releases it. The wait ends
// when ctx is done.
func (s *Store) Lock(ctx context.Context, name string) (func(), error) {
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, name+".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the store directory and a config server name, which is a safe file name
	if err != nil {
		return nil, fmt.Errorf("cannot open the grant lock: %w", bare(err))
	}
	// Holders keep the lock for a refresh at most, bounded by RequestTimeout.
	deadline := time.Now().Add(RequestTimeout + 10*time.Second)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if (!errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR)) || time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("cannot take the grant lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("cannot take the grant lock: %w", ctx.Err())
		case <-time.After(lockPoll):
		}
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("cannot create the grant directory: %w", bare(err))
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return fmt.Errorf("cannot create the grant directory: %w", bare(err))
	}
	if !fi.IsDir() {
		return errors.New("the grant directory is not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(s.dir, 0o700); err != nil { //nolint:gosec // a directory needs its search bit; 0700 is owner only
			return fmt.Errorf("cannot restrict the grant directory to 0700: %w", bare(err))
		}
	}
	return nil
}

func (s *Store) syncDir() error {
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("cannot sync the grant directory: %w", bare(err))
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("cannot sync the grant directory: %w", bare(err))
	}
	return nil
}
