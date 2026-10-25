package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Bounds checked by validation.
const (
	MinMaxMessageBytes = 4 << 10
	MaxMaxMessageBytes = 1 << 30
	MinProbeInterval   = time.Second
	MinMaxBackoff      = time.Second
	maxNameLen         = 64
)

// ServerNameRE is the form of a server name: it becomes the path /<name>/mcp.
var ServerNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

var (
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	inheritRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\*?$`)
	headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// IsReservedHeader reports whether the header is set by mcp-gate or its HTTP client, and so
// cannot be configured.
func IsReservedHeader(name string) bool {
	name = http.CanonicalHeaderKey(name)
	return slices.Contains(reservedHeaders, name) || strings.HasPrefix(name, "Mcp-")
}

// reservedHeaders are set by mcp-gate, its HTTP client or the proxies between; every Mcp-
// header is reserved too, since the SDK sets several (Mcp-Session-Id, Mcp-Protocol-Version,
// Mcp-Method, Mcp-Name, Mcp-Param-*).
var reservedHeaders = []string{
	"Accept", "Accept-Encoding", "Connection", "Content-Length", "Content-Type", "Host",
	"Keep-Alive", "Last-Event-Id", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer",
	"Transfer-Encoding", "Upgrade",
}

// validate records every problem in c, except at the paths in skip (whose values did not
// expand, and so are already reported).
func (c *Config) validate(errs *[]error, skip map[string]bool) {
	add := func(path, format string, args ...any) {
		if skip[path] {
			return
		}
		*errs = append(*errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
	}
	switch c.Version {
	case Version:
	case 0:
		add("version", "is required and must be %d", Version)
	default:
		add("version", "must be %d", Version)
	}
	if len(c.Name) > maxNameLen || strings.ContainsFunc(c.Name, func(r rune) bool { return !unicode.IsPrint(r) }) {
		add("name", "must be at most %d printable characters", maxNameLen)
	}
	if len(c.Servers) == 0 {
		add("servers", "at least one server is required")
	}
	names := make([]string, 0, len(c.Servers))
	for name := range c.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := "servers." + name
		if !ServerNameRE.MatchString(name) {
			// The name is a key the operator wrote, not a value, so it can be shown.
			add(path, "server names are lower-case letters, digits, '.', '_' and '-', start with a letter or digit and are at most 63 characters")
		}
		s := c.Servers[name]
		if s == nil {
			add(path, "is empty")
			continue
		}
		s.validate(path, add)
	}
}

func (s *Server) validate(path string, add func(path, format string, args ...any)) {
	switch {
	case s.Stdio == nil && s.HTTP == nil:
		add(path, "needs stdio or http")
	case s.Stdio != nil && s.HTTP != nil:
		add(path, "has both stdio and http; keep one")
	case s.Stdio != nil:
		s.Stdio.validate(path+".stdio", add)
	default:
		s.HTTP.validate(path+".http", add)
	}
	if s.MaxMessageBytes != nil && (*s.MaxMessageBytes < MinMaxMessageBytes || *s.MaxMessageBytes > MaxMaxMessageBytes) {
		add(path+".maxMessageBytes", "must be between %s and %s", ByteSize(MinMaxMessageBytes), ByteSize(MaxMaxMessageBytes))
	}
	if s.ProtocolVersion != "" && !slices.Contains(mcp.SupportedProtocolVersions(), s.ProtocolVersion) {
		add(path+".protocolVersion", "must be one of %s", strings.Join(mcp.SupportedProtocolVersions(), ", "))
	}
	if s.ProbeInterval != nil && s.ProbeInterval.D() < MinProbeInterval {
		add(path+".probeInterval", "must be at least %s", MinProbeInterval)
	}
	if s.Restart.MaxBackoff != nil && s.Restart.MaxBackoff.D() < MinMaxBackoff {
		add(path+".restart.maxBackoff", "must be at least %s", MinMaxBackoff)
	}
}

func (s *Stdio) validate(path string, add func(path, format string, args ...any)) {
	if s.Command == "" {
		add(path+".command", "is required")
	}
	if s.Cwd != "" && !filepath.IsAbs(s.Cwd) {
		add(path+".cwd", "must be an absolute path")
	}
	for _, k := range sortedKeys(s.Env) {
		if !envNameRE.MatchString(k) {
			add(path+".env", "a variable name is not a valid environment variable name")
		}
	}
	for i, v := range s.InheritEnv {
		if !inheritRE.MatchString(v) {
			add(fmt.Sprintf("%s.inheritEnv[%d]", path, i), "must be a variable name, optionally ending in * to match a prefix")
		}
	}
}

func (h *HTTP) validate(path string, add func(path, format string, args ...any)) {
	if err := CheckURL(h.URL); err != nil {
		add(path+".url", "%v", err)
	}
	seen := map[string]bool{}
	for _, k := range sortedKeys(h.Headers) {
		canonical := http.CanonicalHeaderKey(k)
		switch {
		case seen[canonical]:
			add(path+".headers."+k, "is set twice, in different letter case")
		case !headerNameRE.MatchString(k):
			add(path+".headers", "a header name is not a valid HTTP header name")
		case IsReservedHeader(k):
			add(path+".headers."+k, "is set by mcp-gate and cannot be configured")
		case strings.ContainsAny(h.Headers[k], "\r\n\x00"):
			add(path+".headers."+k, "contains a line break or NUL")
		}
		seen[canonical] = true
	}
}

// CheckURL accepts an absolute http(s) URL without user information or a fragment. Its errors
// never quote the URL, which may carry a credential.
func CheckURL(raw string) error {
	if raw == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a valid URL")
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("must be an http or https URL")
	case u.Host == "":
		return errors.New("must have a host")
	case u.User != nil:
		return errors.New("must not contain user information; use headers for credentials")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("must not contain a fragment")
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
