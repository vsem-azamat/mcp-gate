package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// Bounds checked by validation.
const (
	MinMaxMessageBytes = 4 << 10
	MaxMaxMessageBytes = 1 << 30
	MinProbeInterval   = time.Second
	MinMaxBackoff      = time.Second
	// MaxMaxBackoff keeps connect attempts (backoff plus the 60 s connect timeout) within the
	// 10 minutes in which the OAuth client counts a server's 401s as one run.
	MaxMaxBackoff    = 5 * time.Minute
	MaxEscrowEntries = 100000
	MinFileMaxBytes  = 1 << 10
	MaxFileMaxBytes  = 1 << 30
	maxNameLen       = 64
)

// ServerNameRE is the form of a server name: it becomes the path /<name>/mcp.
var ServerNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

var (
	// keyHashRE is the form of an escrow key hash, which escrow.ParseKeyHash decodes.
	keyHashRE    = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
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

// validate records every problem in c, except at the paths in skip and under them (values that
// did not expand, and policy filters of the wrong form, which are already reported). home is the home directory of the gate's environment,
// or empty.
func (c *Config) validate(errs *[]error, skip map[string]bool, home string) {
	add := func(path, format string, args ...any) {
		if skipped(skip, path) {
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
	c.Listen.validate(add)
	if c.StartupGracePeriod != nil && c.StartupGracePeriod.D() == 0 {
		add("startupGracePeriod", "must be positive")
	}
	if c.LogLevel != "" && !slices.Contains(LogLevels, c.LogLevel) {
		add("logLevel", "must be one of %s", strings.Join(LogLevels, ", "))
	}
	validateTokens("auth.tokens", c.Auth.Tokens, add)
	validateTokens("admin.tokens", c.Admin.Tokens, add)
	c.validateMetrics(add)
	if c.Escrow.TTL != nil && c.Escrow.TTL.D() == 0 {
		add("escrow.ttl", "must be positive")
	}
	if c.Escrow.MaxEntries < 0 || c.Escrow.MaxEntries > MaxEscrowEntries {
		add("escrow.maxEntries", "must be between 0 (the default, %d) and %d", DefaultEscrowMaxEntries, MaxEscrowEntries)
	}
	c.Escrow.validate(add)
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
		if s.Tools != nil && s.Tools.Allow != nil && len(s.Tools.Allow) == 0 {
			c.warn(path+".tools", "an empty allow list exposes every tool, as mcp-proxy's toolFilter did; remove the key to say so")
		}
		if f := s.Redact.Files; f != nil && !f.validateHome(path+".redact.files", home, add) {
			c.FileRootsUnchecked = true
		}
		c.validateServerAuth(name, path+".auth", add)
	}
	c.validateAggregate(add)
	c.validatePolicies(add)
}

// validatePolicies checks that every policy names a token some server accepts and only servers
// that accept it, with filters that cannot be read the way a server's filter of another form
// would be.
func (c *Config) validatePolicies(add func(path, format string, args ...any)) {
	tokens := make([]string, 0, len(c.Policies))
	for name := range c.Policies {
		tokens = append(tokens, name)
	}
	sort.Strings(tokens)
	for _, token := range tokens {
		path := "policies." + token
		p := c.Policies[token]
		if !c.knownToken(token) {
			// Names are keys the operator wrote, not values, so they can be shown.
			add(path, "is not a token in auth.tokens or in a server's auth.tokens")
		}
		if p == nil || len(p.Servers) == 0 {
			add(path+".servers", "must name at least one server")
			continue
		}
		servers := make([]string, 0, len(p.Servers))
		for name := range p.Servers {
			servers = append(servers, name)
		}
		sort.Strings(servers)
		for _, server := range servers {
			sp := path + ".servers." + server
			s := c.Servers[server]
			switch {
			case s == nil:
				add(sp, "is not a server in servers")
				continue
			case s.Auth.Public:
				add(sp, "the server is public and takes no token, so a token policy cannot apply to it")
				continue
			case c.knownToken(token):
				if _, ok := c.EffectiveTokens(server)[token]; !ok {
					add(sp, "the server does not accept the token %s", token)
				}
			}
			if s.Disabled {
				c.warn(sp, "the server is disabled, so the policy has no effect until it is enabled")
			}
			f := p.Servers[server]
			if f == nil || f.Tools == nil && f.Prompts == nil && f.Resources == nil {
				add(sp, "needs at least one of tools, prompts and resources")
				continue
			}
			f.Tools.validate(sp+".tools", "tool", server, add)
			f.Prompts.validate(sp+".prompts", "prompt", server, add)
			f.Resources.validate(sp+".resources", "resource", "", add)
		}
	}
}

// validate checks a policy filter of the kind of entry named by noun. prefix, if set, is the
// server whose name the aggregate endpoint puts before the entries' names, which a policy does
// not use.
func (f *PolicyFilter) validate(path, noun, prefix string, add func(path, format string, args ...any)) {
	if f == nil || f.None {
		return
	}
	if (f.Allow == nil) == (f.Deny == nil) {
		add(path, "needs exactly one of allow and deny, or %s", PolicyNone)
		return
	}
	list, which := f.Allow, "allow"
	if f.Deny != nil {
		list, which = f.Deny, "deny"
	}
	switch {
	case len(list) == 0 && which == "allow":
		key := path[strings.LastIndexByte(path, '.')+1:]
		add(path+".allow", "is empty; a policy takes no empty list, since an empty server tool allow list exposes every tool; write `%s: %s` to hide every %s", key, PolicyNone, noun)
	case len(list) == 0:
		add(path+".deny", "is empty and narrows nothing; remove it")
	}
	seen := map[string]bool{}
	for i, v := range list {
		p := fmt.Sprintf("%s.%s[%d]", path, which, i)
		switch {
		case strings.TrimSpace(v) == "":
			add(p, "cannot be empty")
		case strings.TrimSpace(v) != v:
			add(p, "cannot have surrounding space")
		case seen[v]:
			add(p, "is listed twice")
		case prefix != "" && strings.HasPrefix(v, prefix+AggregateSeparator):
			add(p, "names the %s as the aggregate endpoint does; write the server's own name for it, without %q", noun, prefix+AggregateSeparator)
		}
		seen[v] = true
	}
}

// warn records a problem that does not stop the config from loading.
func (c *Config) warn(path, format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf("%s: %s", path, fmt.Sprintf(format, args...)))
}

// knownToken reports whether name is a token in auth.tokens or in some server's auth.tokens.
func (c *Config) knownToken(name string) bool {
	if _, ok := c.Auth.Tokens[name]; ok {
		return true
	}
	for _, s := range c.Servers {
		if s == nil {
			continue
		}
		if _, ok := s.Auth.Tokens[name]; ok {
			return true
		}
	}
	return false
}

func (c *Config) validateAggregate(add func(path, format string, args ...any)) {
	a := c.Aggregate
	if a == nil {
		return
	}
	if a.Servers != nil && len(a.Servers) == 0 {
		add("aggregate.servers", "must name at least one server; leave it out to serve every server")
	}
	seen := map[string]bool{}
	for i, name := range a.Servers {
		p := fmt.Sprintf("aggregate.servers[%d]", i)
		switch {
		case c.Servers[name] == nil:
			add(p, "is not a server in servers")
		case seen[name]:
			add(p, "is listed twice")
		}
		seen[name] = true
	}
	for _, name := range c.AggregateMembers() {
		switch {
		case strings.Contains(name, AggregateSeparator) || strings.HasSuffix(name, "_"):
			add("servers."+name, "a server on the aggregate endpoint cannot have %q in its name or end in '_', since %q separates it from tool names there; rename it or leave it out of aggregate.servers", AggregateSeparator, AggregateSeparator)
		case len(name)+len(AggregateSeparator)+1 > AggregateMaxName:
			add("servers."+name, "a server on the aggregate endpoint has a name of at most %d characters, so that its prefixed tool names fit in %d; rename it or leave it out of aggregate.servers", AggregateMaxName-len(AggregateSeparator)-1, AggregateMaxName)
		}
	}
}

func (e *Escrow) validate(add func(path, format string, args ...any)) {
	if e.KeyHash != "" {
		if !keyHashRE.MatchString(strings.TrimSpace(e.KeyHash)) {
			add("escrow.keyHash", "is not a hex SHA-256")
		}
	}
	if e.KeyHashFile != "" {
		switch {
		case e.KeyHash != "":
			add("escrow.keyHashFile", "excludes escrow.keyHash; set one of them")
		case !filepath.IsAbs(e.KeyHashFile):
			add("escrow.keyHashFile", "must be an absolute path")
		}
	}
	if e.TCP != nil && !*e.TCP && e.Socket == nil {
		add("escrow.tcp", "false needs escrow.socket: the API would be served nowhere")
	}
	if s := e.Socket; s != nil {
		s.validate(add)
	}
	seen := map[string]bool{}
	for i, a := range e.SourceArguments {
		p := fmt.Sprintf("escrow.sourceArguments[%d]", i)
		switch {
		case strings.TrimSpace(a) == "":
			add(p, "cannot be empty")
		case strings.TrimSpace(a) != a:
			add(p, "cannot have surrounding space")
		case seen[a]:
			add(p, "is listed twice")
		}
		seen[a] = true
	}
}

// maxSocketPath is the longest unix socket path every supported system takes (sun_path is 104
// bytes on darwin, with the terminating NUL).
const maxSocketPath = 103

func (s *EscrowSocket) validate(add func(path, format string, args ...any)) {
	switch {
	case s.Path == "":
		add("escrow.socket.path", "is required")
	case !filepath.IsAbs(s.Path):
		add("escrow.socket.path", "must be an absolute path")
	case len(s.Path) > maxSocketPath:
		add("escrow.socket.path", "must be at most %d bytes, the limit of a unix socket path", maxSocketPath)
	}
	seen := map[int]bool{}
	for i, uid := range s.AllowUIDs {
		p := fmt.Sprintf("escrow.socket.allowUIDs[%d]", i)
		switch {
		case uid < 0 || int64(uid) >= math.MaxUint32:
			add(p, "must be a user ID")
		case seen[uid]:
			add(p, "is listed twice")
		}
		seen[uid] = true
	}
	if s.Mode != nil && *s.Mode > 0o777 {
		add("escrow.socket.mode", "must be permission bits, at most 0777")
	}
}

// TokenNameRE is the form of a token name, which identifies the caller in logs.
var TokenNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func validateTokens(path string, tokens map[string]string, add func(path, format string, args ...any)) {
	for _, name := range sortedKeys(tokens) {
		p := path + "." + name
		if !TokenNameRE.MatchString(name) {
			add(p, "token names are lower-case letters, digits, '.', '_' and '-', start with a letter or digit and are at most 63 characters")
		}
		if v := tokens[name]; v == "" || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			add(p, "must be a non-empty token without spaces or control characters")
		}
	}
}

func (c *Config) validateServerAuth(name, path string, add func(path, format string, args ...any)) {
	a := c.Servers[name].Auth
	validateTokens(path+".tokens", a.Tokens, add)
	if a.Public {
		if len(a.Tokens) > 0 || a.Inherit != nil {
			add(path+".public", "excludes tokens and inherit")
		}
		return
	}
	inherit := a.Inherit == nil || *a.Inherit
	if inherit {
		for _, k := range sortedKeys(a.Tokens) {
			if _, ok := c.Auth.Tokens[k]; ok {
				add(path+".tokens."+k, "is also a global token name; with inherit, the names must differ")
			}
		}
	}
	tokens := c.EffectiveTokens(name)
	if len(tokens) == 0 {
		add(path, "the server accepts no token; add tokens, or set public: true to serve it without one")
	}
	seen := map[string]string{}
	for _, k := range sortedKeys(tokens) {
		if other, ok := seen[tokens[k]]; ok {
			add(path, "the tokens %s and %s have the same value", other, k)
		}
		seen[tokens[k]] = k
	}
}

func (c *Config) validateMetrics(add func(path, format string, args ...any)) {
	m := c.Metrics
	if m.Enabled && len(c.Admin.Tokens) == 0 {
		add("metrics.enabled", "needs admin.tokens, whose tokens may read /_metrics")
	}
	if m.Addr == "" {
		return
	}
	host, port, err := net.SplitHostPort(m.Addr)
	if err != nil || port == "" {
		add("metrics.addr", "must be host:port, such as 127.0.0.1:9464")
		return
	}
	if !LoopbackHost(host) {
		add("metrics.addr", "must be on a loopback address or localhost, since it serves without a token; scrape /_metrics on listen.addr with an admin token from elsewhere")
	}
	listen := c.Listen.Addr
	if listen == "" {
		listen = DefaultListenAddr
	}
	if sameSocket(m.Addr, listen) {
		add("metrics.addr", "must differ from listen.addr")
	}
}

// LoopbackHost reports whether a host, without a port or brackets, is localhost or a loopback
// address.
func LoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// LoopbackAddr reports whether a host:port is on localhost or a loopback address.
func LoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && LoopbackHost(host)
}

// sameSocket reports whether a loopback address metrics would collide with listen: the same
// port, not 0, with listen on every address, on the same address, or either on localhost. It is
// conservative: [::1]:P beside 0.0.0.0:P could bind on some systems, and is still refused.
func sameSocket(metrics, listen string) bool {
	mh, mp, err1 := net.SplitHostPort(metrics)
	lh, lp, err2 := net.SplitHostPort(listen)
	if err1 != nil || err2 != nil || mp != lp || mp == "0" {
		return false
	}
	if lh == "" || strings.EqualFold(mh, "localhost") || strings.EqualFold(lh, "localhost") {
		return true
	}
	ma, err1 := netip.ParseAddr(mh)
	la, err2 := netip.ParseAddr(lh)
	return err1 == nil && err2 == nil && (la.Unmap().IsUnspecified() || ma.Unmap() == la.Unmap())
}

func (l *Listen) validate(add func(path, format string, args ...any)) {
	if l.Addr != "" {
		if _, port, err := net.SplitHostPort(l.Addr); err != nil || port == "" {
			add("listen.addr", "must be host:port, such as 127.0.0.1:9090")
		}
	}
	for i, p := range l.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			add(fmt.Sprintf("listen.trustedProxies[%d]", i), "must be a CIDR, such as 127.0.0.1/32")
		}
	}
	for i, h := range l.AllowedHosts {
		if h == "" || strings.ContainsAny(h, "/ \t@") {
			add(fmt.Sprintf("listen.allowedHosts[%d]", i), "must be a host name, optionally with a port")
		}
	}
}

func (f *Filter) validate(path string, add func(path, format string, args ...any)) {
	if f == nil {
		return
	}
	if (f.Allow == nil) == (f.Deny == nil) {
		add(path, "needs exactly one of allow and deny")
		return
	}
	for i, v := range append(append([]string(nil), f.Allow...), f.Deny...) {
		if strings.TrimSpace(v) == "" {
			add(fmt.Sprintf("%s[%d]", path, i), "cannot be empty")
		}
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
	switch {
	case s.ProtocolVersion != "" && !slices.Contains(mcp.SupportedProtocolVersions(), s.ProtocolVersion):
		add(path+".protocolVersion", "must be one of %s", strings.Join(mcp.SupportedProtocolVersions(), ", "))
	case s.ProtocolVersion >= StatelessVersion && s.HTTP != nil && s.HTTP.SSE():
		add(path+".protocolVersion", "must be earlier than %s, which the sse transport does not carry", StatelessVersion)
	}
	if s.ProbeInterval != nil && s.ProbeInterval.D() < MinProbeInterval {
		add(path+".probeInterval", "must be at least %s", MinProbeInterval)
	}
	if s.Restart.MaxBackoff != nil && (s.Restart.MaxBackoff.D() < MinMaxBackoff || s.Restart.MaxBackoff.D() > MaxMaxBackoff) {
		add(path+".restart.maxBackoff", "must be between %s and %s", FormatDuration(MinMaxBackoff), FormatDuration(MaxMaxBackoff))
	}
	if s.ToolPins != "" && !slices.Contains(ToolPinsModes, s.ToolPins) {
		add(path+".toolPins", "must be one of %s", strings.Join(ToolPinsModes, ", "))
	}
	s.Tools.validate(path+".tools", add)
	s.Prompts.validate(path+".prompts", add)

	s.Resources.validate(path+".resources", add)
	seen := map[string]bool{}
	for i, k := range s.ForwardMeta {
		p := fmt.Sprintf("%s.forwardMeta[%d]", path, i)
		switch {
		case strings.TrimSpace(k) == "":
			add(p, "cannot be empty")
		case seen[k]:
			add(p, "is listed twice")
		case k == "progressToken" || ReservedMetaKey(k):
			add(p, "is a key mcp-gate sets itself: progressToken and keys with an mcp or modelcontextprotocol prefix cannot be forwarded")
		}
		seen[k] = true
	}
	if _, err := redact.New(redact.Options{DisableRules: s.Redact.DisableRules}); err != nil {
		add(path+".redact.disableRules", "names an unknown rule; known: %s", strings.Join(redact.Kinds(), ", "))
	}
	if s.Redact.EscrowTTL != nil && s.Redact.EscrowTTL.D() == 0 {
		add(path+".redact.escrowTTL", "must be positive")
	}
	if f := s.Redact.Files; f != nil {
		if s.Redact.Enabled != nil && !*s.Redact.Enabled {
			add(path+".redact.files", "needs redact.enabled: files are scanned only on a server whose results are redacted")
		}
		f.validate(path+".redact.files", add)
	}
}

// validateHome rejects a root that is home or a directory above it, as written or with its
// symlinks resolved: a download tool's files belong in a directory of their own, and the gate
// would otherwise scan, and could keep, any file in the home directory a result names. It
// reports false when home is unknown (empty or relative), so that nothing could be checked.
func (f *Files) validateHome(path, home string, add func(path, format string, args ...any)) bool {
	if home == "" || !filepath.IsAbs(home) {
		return false
	}
	homes := resolvedForms(home)
	for i, r := range f.Roots {
		if !filepath.IsAbs(r) {
			continue
		}
		if slices.ContainsFunc(resolvedForms(r), func(root string) bool {
			return slices.ContainsFunc(homes, func(h string) bool { return within(root, h) })
		}) {
			add(fmt.Sprintf("%s.roots[%d]", path, i), "must not be $HOME or a directory that contains it")
		}
	}
	return true
}

// resolvedForms returns path cleaned and, when it exists and differs, with its symlinks
// resolved.
func resolvedForms(path string) []string {
	forms := []string{filepath.Clean(path)}
	if r, err := filepath.EvalSymlinks(path); err == nil && r != forms[0] {
		forms = append(forms, r)
	}
	return forms
}

// within reports whether path is dir or lies under it.
func within(dir, path string) bool {
	x, err := filepath.Rel(dir, path)
	return err == nil && x != ".." && !strings.HasPrefix(x, ".."+string(filepath.Separator))
}

func (f *Files) validate(path string, add func(path, format string, args ...any)) {
	if len(f.Tools) == 0 {
		add(path+".tools", "must name at least one tool")
	}
	seen := map[string]bool{}
	for i, t := range f.Tools {
		p := fmt.Sprintf("%s.tools[%d]", path, i)
		switch {
		case strings.TrimSpace(t) == "":
			add(p, "cannot be empty")
		case seen[t]:
			add(p, "is listed twice")
		}
		seen[t] = true
	}
	if len(f.Roots) == 0 {
		add(path+".roots", "must name at least one directory: only files under the roots are scanned")
	}
	for i, r := range f.Roots {
		if !filepath.IsAbs(r) || filepath.Clean(r) == string(filepath.Separator) {
			add(fmt.Sprintf("%s.roots[%d]", path, i), "must be an absolute path other than /")
		}
	}
	if f.MaxBytes != nil && (*f.MaxBytes < MinFileMaxBytes || *f.MaxBytes > MaxFileMaxBytes) {
		add(path+".maxBytes", "must be between %s and %s", ByteSize(MinFileMaxBytes), ByteSize(MaxFileMaxBytes))
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

// StatelessVersion is the first protocol version negotiated by server/discover, which only stdio
// and streamable HTTP carry; downstream.StatelessVersion is the same, as a gate test checks.
const StatelessVersion = "2026-07-28"

func (h *HTTP) validate(path string, add func(path, format string, args ...any)) {
	if err := CheckURL(h.URL); err != nil {
		add(path+".url", "%v", err)
	}
	switch h.Transport {
	case "", TransportStreamable, TransportSSE:
	default:
		add(path+".transport", "must be %s or %s", TransportStreamable, TransportSSE)
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
	if h.OAuth != nil {
		if _, ok := seen["Authorization"]; ok {
			add(path+".headers.Authorization", "cannot be set with oauth, which sets it")
		}
		if err := CheckURL(h.URL); err == nil && !SecureURL(h.URL) {
			add(path+".url", "must be an https URL, or http on a loopback address, with oauth")
		}
		h.OAuth.validate(path+".oauth", add)
	}
}

func (o *OAuth) validate(path string, add func(path, format string, args ...any)) {
	if o.ClientSecret != "" && o.ClientID == "" {
		add(path+".clientSecret", "needs clientID")
	}
	if o.ClientID != "" && strings.ContainsFunc(o.ClientID, unicode.IsControl) {
		add(path+".clientID", "contains a control character")
	}
	if o.RedirectURL != "" {
		if err := CheckURL(o.RedirectURL); err != nil {
			add(path+".redirectURL", "%v", err)
		} else if !SecureURL(o.RedirectURL) {
			add(path+".redirectURL", "must be an https URL, or http on a loopback address")
		}
	}
	if o.AuthServerMetadataURL != "" {
		if err := CheckURL(o.AuthServerMetadataURL); err != nil {
			add(path+".authServerMetadataURL", "%v", err)
		} else if !SecureURL(o.AuthServerMetadataURL) {
			add(path+".authServerMetadataURL", "must be an https URL, or http on a loopback address")
		}
	}
	seen := map[string]bool{}
	for i, sc := range o.Scopes {
		p := fmt.Sprintf("%s.scopes[%d]", path, i)
		switch {
		case sc == "" || strings.ContainsFunc(sc, func(r rune) bool { return r <= ' ' || r == '"' || r == '\\' || r > '~' }):
			add(p, "must be a scope token: printable ASCII without spaces, quotes or backslashes")
		case seen[sc]:
			add(p, "is listed twice")
		}
		seen[sc] = true
	}
}

// SecureURL reports whether a valid absolute URL is https, or http on a loopback address, and
// so may carry an OAuth credential.
func SecureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		if strings.EqualFold(h, "localhost") {
			return true
		}
		ip, err := netip.ParseAddr(h)
		return err == nil && ip.IsLoopback()
	}
	return false
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

// ReservedMetaKey reports whether a _meta key has a prefix the MCP specification reserves: one
// whose labels include "modelcontextprotocol" or "mcp", such as "io.modelcontextprotocol/".
func ReservedMetaKey(k string) bool {
	prefix, _, ok := strings.Cut(k, "/")
	if !ok {
		return false
	}
	for label := range strings.SplitSeq(prefix, ".") {
		if label == "modelcontextprotocol" || label == "mcp" {
			return true
		}
	}
	return false
}

// skipped reports whether path is in skip or under a path in skip.
func skipped(skip map[string]bool, path string) bool {
	for p := range skip {
		if path == p || strings.HasPrefix(path, p+".") || strings.HasPrefix(path, p+"[") {
			return true
		}
	}
	return false
}
