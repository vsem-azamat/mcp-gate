// Package config reads and validates the mcp-gate configuration file.
//
// The file is YAML, decoded strictly: unknown keys, duplicate keys, a second document and bare
// numbers where a duration or size is expected are errors. After decoding, every string value is
// expanded: ${VAR} is replaced by the variable's value, $$ by a literal $, and an unset or empty
// variable is an error. Expansion runs on the decoded values, so a variable's value can never
// change the structure of the file.
//
// The schema holds only the keys this build implements. Errors name the field path and never
// the value, since values may hold credentials.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Version is the only config file version this build reads.
const Version = 1

// Defaults applied to keys that are left out.
const (
	DefaultName               = "mcp-gate"
	DefaultListenAddr         = "127.0.0.1:9090"
	DefaultStartupGracePeriod = 30 * time.Second
	DefaultLogLevel           = "info"
	DefaultMaxMessageBytes    = 16 << 20
	DefaultProbeInterval      = 30 * time.Second
	DefaultMaxBackoff         = 30 * time.Second
	DefaultEscrowTTL          = 24 * time.Hour
	DefaultEscrowMaxEntries   = 1000
	DefaultFileMaxBytes       = 20 << 20
	DefaultEscrowSocketMode   = FileMode(0o600)
)

// DefaultTrustedProxies are the peers whose X-Forwarded-For is read when behindProxy is set
// and trustedProxies is left out: a reverse proxy on the same host.
var DefaultTrustedProxies = []string{"127.0.0.1/32", "::1/128"}

// LogLevels are the values logLevel takes.
var LogLevels = []string{"debug", "info", "warn", "error"}

// DefaultInheritEnv is what a stdio child inherits from the gate's environment when its
// inheritEnv is left out. A trailing * matches a prefix.
var DefaultInheritEnv = []string{"PATH", "HOME", "LANG", "LC_*", "TZ", "USER", "XDG_RUNTIME_DIR"}

// PartialMarker marks a key that mcp-gate import --partial dropped. A file that contains it in a
// comment is rejected, so a partial import is never used by accident.
const PartialMarker = "NOT IMPLEMENTED IN THIS BUILD"

// Config is a loaded configuration with defaults applied.
type Config struct {
	Version int `yaml:"version"`
	// FileRootsUnchecked is set by Parse when a server scans files but $HOME was unset or
	// relative, so its file roots could not be checked against it.
	FileRootsUnchecked bool `yaml:"-"`
	// Name is sent as the client name to downstream servers and named by /_healthz and /_readyz.
	Name   string `yaml:"name,omitempty"`
	Listen Listen `yaml:"listen,omitempty"`
	// StartupGracePeriod bounds how long /_readyz reports "initializing" while servers connect.
	StartupGracePeriod *Duration `yaml:"startupGracePeriod,omitempty"`
	// LogLevel is the lowest level logged: debug, info, warn or error.
	LogLevel string `yaml:"logLevel,omitempty"`
	// Auth holds the client tokens every server accepts unless it opts out.
	Auth Tokens `yaml:"auth,omitempty"`
	// Admin holds the tokens that may read /_status.
	Admin Tokens `yaml:"admin,omitempty"`
	// Escrow configures the secret escrow, which is on when its key hash is in the config or the
	// environment.
	Escrow Escrow `yaml:"escrow,omitempty"`
	// Aggregate, if set, serves the tools, prompts and resources of several servers at
	// AggregatePath.
	Aggregate *Aggregate         `yaml:"aggregate,omitempty"`
	Servers   map[string]*Server `yaml:"servers"`
}

// AggregatePath is the route of the aggregate endpoint. It has one segment, so it never
// collides with a server's /<name>/mcp.
const AggregatePath = "/mcp"

// AggregateSeparator joins a server's name and a tool or prompt name in the aggregate catalog;
// the name of a member server cannot hold it.
const AggregateSeparator = "__"

// AggregateMaxName is the longest tool or prompt name the aggregate catalog serves, the limit many
// clients put on tool names. A member's name leaves room in it for the separator and one more
// character.
const AggregateMaxName = 64

// Aggregate configures the aggregate endpoint.
type Aggregate struct {
	// Servers are the servers it serves; nil means every enabled server. A disabled server is
	// left out.
	Servers []string `yaml:"servers,omitempty"`
	Log     Log      `yaml:"log,omitempty"`
}

// AggregateMembers returns the enabled servers the aggregate endpoint serves, sorted; nil when
// it is off.
func (c *Config) AggregateMembers() []string {
	if c.Aggregate == nil {
		return nil
	}
	var out []string
	if c.Aggregate.Servers == nil {
		for name, s := range c.Servers {
			if s != nil && !s.Disabled {
				out = append(out, name)
			}
		}
	} else {
		for _, name := range c.Aggregate.Servers {
			if s := c.Servers[name]; s != nil && !s.Disabled && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Escrow configures the secret escrow.
type Escrow struct {
	// TTL is how long a kept secret stays retrievable, unless its server sets redact.escrowTTL.
	TTL *Duration `yaml:"ttl,omitempty"`
	// MaxEntries caps the entries held; the oldest is evicted. 0 means the default.
	MaxEntries int `yaml:"maxEntries,omitempty"`
	// KeyHash is the hex SHA-256 of the API key, usually ${VAR}. It excludes KeyHashFile.
	KeyHash string `yaml:"keyHash,omitempty"`
	// KeyHashFile is the absolute path of a file that holds the hex SHA-256 of the API key, such
	// as a systemd credential; it is read at start.
	KeyHashFile string `yaml:"keyHashFile,omitempty"`
	// SourceArguments are the request arguments copied into an entry's source summary; nil
	// means escrow.DefaultSourceArguments and an empty list copies none.
	SourceArguments []string `yaml:"sourceArguments,omitempty"`
	// KeyHashVars are the environment variables KeyHash was expanded from, which the gate keeps
	// from its children as it keeps the key hash variables. Set by Parse, not by the file.
	KeyHashVars []string `yaml:"-"`
	// TCP serves the API at /_escrow/ on the listener; nil means true.
	TCP *bool `yaml:"tcp,omitempty"`
	// Socket, if set, also serves the API on a unix socket.
	Socket *EscrowSocket `yaml:"socket,omitempty"`
}

// EscrowSocket serves the escrow API on a unix socket, where peers whose user ID is allowed need
// no key.
type EscrowSocket struct {
	// Path is the absolute path of the socket.
	Path string `yaml:"path"`
	// AllowUIDs are the user IDs of peers served without a key, unless the peer is the gate or
	// its descendant (on Linux); nil or empty means none.
	AllowUIDs []int `yaml:"allowUIDs,omitempty"`
	// Mode is the socket file's permission bits; nil means DefaultEscrowSocketMode.
	Mode *FileMode `yaml:"mode,omitempty"`
}

// Listen configures the upstream listener.
type Listen struct {
	// Addr is the host:port to listen on.
	Addr string `yaml:"addr,omitempty"`
	// BehindProxy turns off the SDK's check that a request to a loopback address names a
	// loopback Host, and reads X-Forwarded-For from TrustedProxies.
	BehindProxy bool `yaml:"behindProxy,omitempty"`
	// TrustedProxies are the CIDRs of peers whose X-Forwarded-For is believed; nil means
	// DefaultTrustedProxies.
	TrustedProxies []string `yaml:"trustedProxies"`
	// AllowedHosts, if not empty, are the only Host values the MCP routes accept.
	AllowedHosts []string `yaml:"allowedHosts,omitempty"`
}

// Tokens maps token names to secrets. The name identifies the caller in logs.
type Tokens struct {
	Tokens map[string]string `yaml:"tokens,omitempty"`
}

// Server is one downstream MCP server. Exactly one of Stdio and HTTP is set.
type Server struct {
	Stdio *Stdio `yaml:"stdio,omitempty"`
	HTTP  *HTTP  `yaml:"http,omitempty"`
	// CallTimeout bounds each request to the server; 0 means no bound.
	CallTimeout Duration `yaml:"callTimeout"`
	// MaxMessageBytes caps one stdio frame or one HTTP response body or event.
	MaxMessageBytes *ByteSize `yaml:"maxMessageBytes,omitempty"`
	// ProtocolVersion, if set, pins the protocol version offered to the server.
	ProtocolVersion string `yaml:"protocolVersion,omitempty"`
	// ProbeInterval is the time between liveness probes.
	ProbeInterval *Duration `yaml:"probeInterval,omitempty"`
	Restart       Restart   `yaml:"restart,omitempty"`
	Disabled      bool      `yaml:"disabled,omitempty"`

	// Tools, Prompts and Resources select what the server exposes; nil exposes everything.
	Tools     *Filter    `yaml:"tools,omitempty"`
	Prompts   *Filter    `yaml:"prompts,omitempty"`
	Resources *Filter    `yaml:"resources,omitempty"`
	Auth      ServerAuth `yaml:"auth,omitempty"`
	Log       Log        `yaml:"log,omitempty"`
	Redact    Redact     `yaml:"redact,omitempty"`
	// ForwardMeta lists the _meta keys of a client request that are passed to the server, by
	// exact name. Others are dropped.
	ForwardMeta []string `yaml:"forwardMeta,omitempty"`
}

// Filter is an allow list or a deny list; exactly one is set.
type Filter struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// ServerAuth selects the tokens a server accepts.
type ServerAuth struct {
	// Inherit adds the global auth.tokens to the server's own; nil means true.
	Inherit *bool `yaml:"inherit,omitempty"`
	// Tokens are accepted by this server only.
	Tokens map[string]string `yaml:"tokens,omitempty"`
	// Public serves the server without a token. It excludes tokens.
	Public bool `yaml:"public,omitempty"`
}

// Log configures per-server logging.
type Log struct {
	// Requests logs every HTTP request to the server's route.
	Requests bool `yaml:"requests,omitempty"`
}

// Redact configures the redaction of the server's results.
type Redact struct {
	// Enabled redacts results; nil means true.
	Enabled *bool `yaml:"enabled,omitempty"`
	// RU adds the Russian credential-label rules.
	RU bool `yaml:"ru,omitempty"`
	// HighEntropy adds the high-entropy heuristic.
	HighEntropy bool `yaml:"highEntropy,omitempty"`
	// DisableRules lists rule kinds that are never reported.
	DisableRules []string `yaml:"disableRules,omitempty"`
	// Escrow keeps this server's findings and files in the escrow when it is on; nil means true.
	// False gives them the plain [REDACTED:<kind>] marker and keeps nothing.
	Escrow *bool `yaml:"escrow,omitempty"`
	// EscrowTTL is how long the escrow keeps this server's secrets; nil means escrow.ttl.
	EscrowTTL *Duration `yaml:"escrowTTL,omitempty"`
	// Files configures the scanning of files the server's download tools write.
	Files *Files `yaml:"files,omitempty"`
}

// Files configures file scanning.
type Files struct {
	// Tools are the tools that write a file and report its path.
	Tools []string `yaml:"tools"`
	// Roots are the absolute directories the files are written under; only files there are
	// scanned.
	Roots []string `yaml:"roots"`
	// MaxBytes is the largest file scanned; a larger text file withholds its result.
	MaxBytes *ByteSize `yaml:"maxBytes,omitempty"`
}

// EffectiveTokens returns the tokens server name accepts, by name; nil for a public server.
func (c *Config) EffectiveTokens(name string) map[string]string {
	s := c.Servers[name]
	if s == nil || s.Auth.Public {
		return nil
	}
	out := make(map[string]string, len(c.Auth.Tokens)+len(s.Auth.Tokens))
	if s.Auth.Inherit == nil || *s.Auth.Inherit {
		for k, v := range c.Auth.Tokens {
			out[k] = v
		}
	}
	for k, v := range s.Auth.Tokens {
		out[k] = v
	}
	return out
}

// Stdio starts the server as a child process that speaks MCP on stdin and stdout.
type Stdio struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args,omitempty"`
	// Cwd is the child's working directory; empty is the gate's.
	Cwd string `yaml:"cwd,omitempty"`
	// Env is set in the child's environment and wins over inherited values.
	Env map[string]string `yaml:"env,omitempty"`
	// InheritEnv names the gate's variables the child inherits; nil means DefaultInheritEnv
	// and an empty list means none.
	InheritEnv []string `yaml:"inheritEnv"`
}

// HTTP connects to the server over streamable HTTP.
type HTTP struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers,omitempty"`
	// OAuth, if set, authorizes the requests with an OAuth grant obtained by mcp-gate auth login.
	OAuth *OAuth `yaml:"oauth,omitempty"`
}

// OAuth configures the OAuth client of an HTTP server. Every key is optional: by default the
// authorization server is discovered from the server and the client registers dynamically.
type OAuth struct {
	// ClientID names a client registered with the authorization server in advance; empty
	// registers one dynamically at login.
	ClientID string `yaml:"clientID,omitempty"`
	// ClientSecret is the secret of ClientID, for a confidential client.
	ClientSecret string `yaml:"clientSecret,omitempty"`
	// RedirectURL is where the authorization server sends the browser after sign-in.
	RedirectURL string `yaml:"redirectURL,omitempty"`
	// Scopes, if set, are requested instead of the scopes the server advertises.
	Scopes []string `yaml:"scopes,omitempty"`
	// AuthServerMetadataURL, if set, is where the authorization server's metadata is read,
	// instead of the well-known locations under its issuer.
	AuthServerMetadataURL string `yaml:"authServerMetadataURL,omitempty"`
}

// DefaultRedirectURL is the redirect URL of an OAuth client that sets none. Nothing listens on
// it: mcp-gate auth login asks for the address the browser was sent to.
const DefaultRedirectURL = "http://localhost:8090/oauth/callback"

// Restart configures restarts after a failure.
type Restart struct {
	// MaxBackoff caps the delay between restarts.
	MaxBackoff *Duration `yaml:"maxBackoff,omitempty"`
}

// LookupFunc reads an environment variable, like os.LookupEnv.
type LookupFunc func(name string) (string, bool)

// Load reads and validates the file at path.
func Load(path string, lookup LookupFunc) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own config file
	if err != nil {
		return nil, err
	}
	return Parse(data, lookup)
}

// Parse decodes, expands and validates a config file. All problems found are returned together,
// joined, each naming its field.
func Parse(data []byte, lookup LookupFunc) (*Config, error) {
	if err := rejectPartial(data); err != nil {
		return nil, err
	}
	if err := rejectNullAggregate(data); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("config: %s", withoutValues(err))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: holds more than one YAML document")
	}
	var errs []error
	skip := map[string]bool{}
	keyHashVars := varNames(c.Escrow.KeyHash)
	expandAll(&c, lookup, &errs, skip)
	c.Escrow.KeyHashVars = keyHashVars
	home, _ := lookup("HOME")
	c.validate(&errs, skip, home)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	c.applyDefaults()
	return &c, nil
}

// rejectPartial fails when a comment carries PartialMarker.
func rejectPartial(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	var found bool
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		for _, c := range []string{n.HeadComment, n.LineComment, n.FootComment} {
			if strings.Contains(c, PartialMarker) {
				found = true
			}
		}
		for _, k := range n.Content {
			walk(k)
		}
	}
	walk(&doc)
	if found {
		return fmt.Errorf("config: it was written by mcp-gate import --partial and has keys marked %q; "+
			"remove those keys and their comments once you accept dropping them", PartialMarker)
	}
	return nil
}

// rejectNullAggregate fails when the top-level aggregate key has no value, which would decode to
// the endpoint being off although the key is written.
func rejectNullAggregate(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil //nolint:nilerr // the decoder reports a malformed file with its own error
	}
	top := doc.Content[0].Content
	for i := 0; i+1 < len(top); i += 2 {
		if top[i].Value == "aggregate" && top[i+1].Tag == "!!null" {
			return errors.New("aggregate: has no value; write `aggregate: {}` to serve every server at " + AggregatePath + ", or remove the key")
		}
	}
	return nil
}

// quotedRE matches the values the YAML decoder quotes in its errors.
var quotedRE = regexp.MustCompile("`[^`]*`")

// withoutValues returns the decoder's error text with the values it quotes removed.
func withoutValues(err error) string {
	return quotedRE.ReplaceAllString(err.Error(), "(value not shown)")
}

func (c *Config) applyDefaults() {
	if c.Name == "" {
		c.Name = DefaultName
	}
	if c.Listen.Addr == "" {
		c.Listen.Addr = DefaultListenAddr
	}
	if c.Listen.TrustedProxies == nil {
		c.Listen.TrustedProxies = append([]string(nil), DefaultTrustedProxies...)
	}
	if c.StartupGracePeriod == nil {
		v := Duration(DefaultStartupGracePeriod)
		c.StartupGracePeriod = &v
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.Escrow.TTL == nil {
		v := Duration(DefaultEscrowTTL)
		c.Escrow.TTL = &v
	}
	if c.Escrow.MaxEntries == 0 {
		c.Escrow.MaxEntries = DefaultEscrowMaxEntries
	}
	if c.Escrow.TCP == nil {
		c.Escrow.TCP = new(true)
	}
	if s := c.Escrow.Socket; s != nil && s.Mode == nil {
		v := DefaultEscrowSocketMode
		s.Mode = &v
	}
	for _, s := range c.Servers {
		if s.Redact.EscrowTTL == nil {
			v := *c.Escrow.TTL
			s.Redact.EscrowTTL = &v
		}
		if f := s.Redact.Files; f != nil && f.MaxBytes == nil {
			v := ByteSize(DefaultFileMaxBytes)
			f.MaxBytes = &v
		}
		if s.Redact.Enabled == nil {
			s.Redact.Enabled = new(true)
		}
		if s.Redact.Escrow == nil {
			s.Redact.Escrow = new(true)
		}
		if s.Auth.Inherit == nil && !s.Auth.Public {
			s.Auth.Inherit = new(true)
		}
		if s.MaxMessageBytes == nil {
			v := ByteSize(DefaultMaxMessageBytes)
			s.MaxMessageBytes = &v
		}
		if s.ProbeInterval == nil {
			v := Duration(DefaultProbeInterval)
			s.ProbeInterval = &v
		}
		if s.Restart.MaxBackoff == nil {
			v := Duration(DefaultMaxBackoff)
			s.Restart.MaxBackoff = &v
		}
		if s.HTTP != nil && s.HTTP.OAuth != nil && s.HTTP.OAuth.RedirectURL == "" {
			s.HTTP.OAuth.RedirectURL = DefaultRedirectURL
		}
		if s.Stdio != nil && s.Stdio.InheritEnv == nil {
			s.Stdio.InheritEnv = append([]string(nil), DefaultInheritEnv...)
		}
	}
}
