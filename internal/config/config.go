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
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Version is the only config file version this build reads.
const Version = 1

// Defaults applied to keys that are left out.
const (
	DefaultName            = "mcp-gate"
	DefaultMaxMessageBytes = 16 << 20
	DefaultProbeInterval   = 30 * time.Second
	DefaultMaxBackoff      = 30 * time.Second
)

// DefaultInheritEnv is what a stdio child inherits from the gate's environment when its
// inheritEnv is left out. A trailing * matches a prefix.
var DefaultInheritEnv = []string{"PATH", "HOME", "LANG", "LC_*", "TZ", "USER", "XDG_RUNTIME_DIR"}

// PartialMarker marks a key that mcp-gate import --partial dropped. A file that contains it in a
// comment is rejected, so a partial import is never used by accident.
const PartialMarker = "NOT IMPLEMENTED IN THIS BUILD"

// Config is a loaded configuration with defaults applied.
type Config struct {
	Version int `yaml:"version"`
	// Name is sent as the client name to downstream servers.
	Name    string             `yaml:"name,omitempty"`
	Servers map[string]*Server `yaml:"servers"`
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
}

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
	expandAll(&c, lookup, &errs, skip)
	c.validate(&errs, skip)
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
	for _, s := range c.Servers {
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
		if s.Stdio != nil && s.Stdio.InheritEnv == nil {
			s.Stdio.InheritEnv = append([]string(nil), DefaultInheritEnv...)
		}
	}
}
