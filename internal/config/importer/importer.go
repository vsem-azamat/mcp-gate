// Package importer converts an mcp-proxy config.json into an mcp-gate config.
//
// It maps only the keys this build implements. Any other key that changes behaviour makes the
// import fail with the list of such keys; with Partial set, the config is written anyway, each
// dropped key marked with config.PartialMarker, and the config loader rejects that output until
// the marks are removed. Keys that mcp-proxy itself ignored, and options that have no effect, are
// dropped with a comment. Messages name keys but never values.
package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// Options configures an import.
type Options struct {
	// Partial writes the config even when keys are not implemented by this build.
	Partial bool
}

// Result is a finished import.
type Result struct {
	// YAML is the mcp-gate config.
	YAML []byte
	// Unimplemented lists the keys this build does not implement, by their path in the input.
	Unimplemented []string
	// Warnings are notes for the operator; none quotes a value.
	Warnings []string
}

// UnimplementedError is returned when keys are not implemented and Partial is not set.
type UnimplementedError struct{ Keys []string }

func (e *UnimplementedError) Error() string {
	return "these mcp-proxy keys are not implemented by this build of mcp-gate (use --partial to drop them):\n  " +
		strings.Join(e.Keys, "\n  ")
}

// Import converts data, an mcp-proxy config.json, into an mcp-gate config.
func Import(data []byte, opts Options) (*Result, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, errors.New("the input is not valid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the input holds more than one JSON value")
	}
	im := &importer{}
	doc, err := im.root(root)
	if err != nil {
		return nil, err
	}
	sort.Strings(im.unimplemented)
	if len(im.unimplemented) > 0 && !opts.Partial {
		return nil, &UnimplementedError{Keys: im.unimplemented}
	}
	out, err := doc.render(im.unimplemented)
	if err != nil {
		return nil, err
	}
	return &Result{YAML: out, Unimplemented: im.unimplemented, Warnings: im.warnings}, nil
}

type importer struct {
	unimplemented []string
	warnings      []string
}

func (im *importer) notImplemented(path string) { im.unimplemented = append(im.unimplemented, path) }

func (im *importer) warn(format string, args ...any) {
	im.warnings = append(im.warnings, fmt.Sprintf(format, args...))
}

// ignored warns about keys mcp-proxy did not read either.
func (im *importer) ignored(o *object) {
	for _, k := range o.rest() {
		im.warn("%s.%s is not an mcp-proxy key and is dropped", o.path, k)
	}
}

// document is the config being written.
type document struct {
	notes   []string // comments at the top
	name    string
	addr    string
	grace   *time.Duration
	tokens  []string          // the global client tokens, converted
	names   map[string]string // token value to token name
	servers []*server
	// escrowTTL and maxEntries are the global escrow settings.
	escrowTTL  *time.Duration
	maxEntries int64
}

type server struct {
	name     string
	notes    []string // comments above the server
	stdio    *config.Stdio
	inherit  string // comment on inheritEnv
	http     *config.HTTP
	timeout  time.Duration
	tNote    string // comment on callTimeout
	probe    *time.Duration
	backoff  *time.Duration
	disabled bool

	filters  [3]*config.Filter // tools, prompts, resources
	fNotes   [3]string         // comments on the filters
	tokens   []string          // own tokens replacing the global ones; nil inherits
	public   string            // set to a comment when the server needs no token
	requests bool              // log.requests
	redact   redactBlock
}

// options are the mcp-proxy options of the proxy or of one server.
type options struct {
	pingInterval, reconnectInterval *time.Duration
	disabled                        bool
	notes                           []string
	tokens                          []string // authTokens, converted; nil when absent
	logEnabled                      *bool
	redact                          *redactBlock
	filters                         [3]*config.Filter
	fNotes                          [3]string
}

// redactBlock is an mcp-proxy redact block.
type redactBlock struct {
	present, enabled, highEntropy bool
	disableRules                  []string
	escrowTTL                     *time.Duration
	maxEntries                    int64 // escrowMaxEntries, read from the global block only
	files                         *config.Files
	path                          string // of the block in the input
}

func (im *importer) root(v any) (*document, error) {
	root, err := newObject("$", v)
	if err != nil {
		return nil, errors.New("the input must be a JSON object")
	}
	root.path = ""
	for _, legacy := range []string{"server", "clients"} {
		if _, ok, _ := root.get(legacy); ok {
			return nil, errors.New(`this is an mcp-proxy v1 config ("server" and "clients"); convert it to v2 ("mcpProxy" and "mcpServers") first`)
		}
	}
	doc := &document{}
	proxy, err := root.object("mcpProxy")
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return nil, errors.New("mcpProxy is required")
	}
	proxy.path = "mcpProxy"
	global, err := im.proxy(proxy, doc)
	if err != nil {
		return nil, err
	}
	if r := global.redact; r != nil {
		doc.escrowTTL, doc.maxEntries = r.escrowTTL, r.maxEntries
	}
	servers, err := root.object("mcpServers")
	if err != nil {
		return nil, err
	}
	if servers == nil || len(servers.m) == 0 {
		return nil, errors.New("mcpServers is empty")
	}
	servers.path = "mcpServers"
	root.path = "$"
	im.ignored(root)
	names := make([]string, 0, len(servers.m))
	for name := range servers.m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s, err := im.server(servers, name, global)
		if err != nil {
			return nil, err
		}
		if s != nil {
			doc.servers = append(doc.servers, s)
		}
	}
	if len(doc.servers) == 0 {
		return nil, errors.New("no server could be imported")
	}
	doc.tokens = global.tokens
	im.nameTokens(doc)
	doc.notes = append(doc.notes, "mcp-proxy passed each request's _meta to the server as it was; mcp-gate passes only the keys a server lists in forwardMeta, none by default.")
	if slices.ContainsFunc(doc.servers, func(s *server) bool { return s.requests }) {
		doc.notes = append(doc.notes, "logEnabled also turned on the MCP logging capability; mcp-gate does not offer it, and logs requests only.")
	}
	if slices.ContainsFunc(doc.servers, func(s *server) bool { return s.stdio != nil }) {
		doc.notes = append(doc.notes, "stdio servers no longer inherit the whole environment: only inheritEnv (default "+
			strings.Join(config.DefaultInheritEnv, " ")+") and env.")
	}
	return doc, nil
}

func (im *importer) proxy(p *object, doc *document) (*options, error) {
	name, ok, err := p.str("name")
	if err != nil {
		return nil, err
	}
	if ok {
		name = convertVars(name, &im.warnings, p.sub("name"))
		if len(name) <= 64 && !strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) {
			doc.name = name
		} else {
			im.warn("mcpProxy.name is too long or not printable and is dropped")
		}
	}
	if _, ok, _ := p.get("version"); ok {
		doc.notes = append(doc.notes, "mcpProxy.version is dropped: mcp-gate reports its own version.")
	}
	if err := im.listen(p, doc); err != nil {
		return nil, err
	}
	typ, ok, err := p.str("type")
	if err != nil {
		return nil, err
	}
	switch {
	case ok && typ == "streamable-http":
		doc.notes = append(doc.notes, "mcpProxy.type is dropped: mcp-gate serves streamable HTTP.")
	case ok:
		im.notImplemented("mcpProxy.type (" + safeWord(typ) + "): mcp-gate serves streamable HTTP only")
	default:
		im.notImplemented("mcpProxy.type (absent, so SSE): mcp-gate serves streamable HTTP only")
	}
	global := &options{}
	if o, err := p.object("options"); err != nil {
		return nil, err
	} else if o != nil {
		if global, err = im.options(o, true); err != nil {
			return nil, err
		}
		doc.notes = append(doc.notes, global.notes...)
	}
	im.ignored(p)
	return global, nil
}

// options reads an options block. For the proxy's block, global is true: mcp-proxy copies only
// some of its keys into each server.
func (im *importer) options(o *object, global bool) (*options, error) {
	out := &options{}
	if _, ok, _ := o.get("panicIfInvalid"); ok {
		out.notes = append(out.notes, o.path+".panicIfInvalid is dropped: it has no equivalent.")
	}
	if err := im.serving(o, global, out); err != nil {
		return nil, err
	}
	disabled, ok, err := o.boolean("disabled")
	if err != nil {
		return nil, err
	}
	if ok && global {
		im.warn("%s.disabled is dropped: mcp-proxy does not apply it to servers", o.path)
	}
	out.disabled = disabled
	if d, ok, err := o.duration("pingInterval"); err != nil {
		return nil, err
	} else if ok && d > 0 {
		out.pingInterval = &d
	}
	if d, ok, err := o.duration("reconnectInterval"); err != nil {
		return nil, err
	} else if ok && d > 0 {
		out.reconnectInterval = &d
	}
	if _, ok, err := o.boolean("autoReconnect"); err != nil {
		return nil, err
	} else if ok {
		out.notes = append(out.notes, o.path+".autoReconnect is dropped: mcp-gate always restarts a failed server, with backoff up to restart.maxBackoff.")
	}
	im.ignored(o)
	return out, nil
}

func (im *importer) server(servers *object, name string, global *options) (*server, error) {
	o, err := servers.object(name)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, fmt.Errorf("mcpServers.%s: must be an object", name)
	}
	if !config.ServerNameRE.MatchString(name) {
		return nil, fmt.Errorf("mcpServers.%s: mcp-gate server names are lower-case letters, digits, '.', '_' and '-' and start with a letter or digit; rename the server (its path /%s/mcp changes too)", name, name)
	}
	s := &server{name: name}
	transport, _, err := o.str("transportType")
	if err != nil {
		return nil, err
	}
	command, hasCommand, err := o.str("command")
	if err != nil {
		return nil, err
	}
	url, hasURL, err := o.str("url")
	if err != nil {
		return nil, err
	}
	if hasCommand && hasURL {
		return nil, fmt.Errorf("%s: command and url are mutually exclusive", o.path)
	}
	if transport == "" {
		switch {
		case hasCommand:
			transport = "stdio"
		case hasURL:
			transport = "sse"
		default:
			return nil, fmt.Errorf("%s: command or url is required", o.path)
		}
	}
	timeout, hasTimeout, err := o.duration("timeout")
	if err != nil {
		return nil, err
	}
	switch transport {
	case "stdio":
		if !hasCommand || command == "" {
			return nil, fmt.Errorf("%s: command is required for stdio", o.path)
		}
		if err := im.stdio(o, s, command); err != nil {
			return nil, err
		}
		if _, ok, _ := o.get("oauth"); ok {
			im.warn("%s.oauth is dropped: mcp-proxy ignores oauth for stdio", o.path)
		}
		if hasTimeout && timeout > 0 && timeout < time.Millisecond {
			s.tNote = "mcp-proxy discarded its sub-millisecond timeout, so it had none"
			timeout = 0
		}
	case "streamable-http", "sse":
		if !hasURL || url == "" {
			return nil, fmt.Errorf("%s: url is required for %s", o.path, transport)
		}
		if err := im.http(o, s, url); err != nil {
			return nil, err
		}
		if transport == "sse" {
			s.http.Transport = config.TransportSSE
		}
		if s.http.OAuth, err = im.oauth(o); err != nil {
			return nil, err
		}
		if timeout > 0 && timeout < time.Millisecond {
			return nil, fmt.Errorf("%s.timeout: is shorter than a millisecond; mcp-proxy rejects it too", o.path)
		}
	default:
		return nil, fmt.Errorf("%s.transportType: must be stdio, sse or streamable-http", o.path)
	}
	s.timeout = timeout
	if !hasTimeout {
		s.tNote = "mcp-proxy had no timeout for this server"
	}
	local := &options{}
	if opts, err := o.object("options"); err != nil {
		return nil, err
	} else if opts != nil {
		if local, err = im.options(opts, false); err != nil {
			return nil, err
		}
	}
	s.notes = append(s.notes, local.notes...)
	s.disabled = local.disabled
	im.applyServing(o.path, s, local, global)
	s.probe = cmpOr(local.pingInterval, global.pingInterval)
	s.backoff = cmpOr(local.reconnectInterval, global.reconnectInterval)
	s.probe = im.atLeast(s.probe, config.MinProbeInterval, o.path+": the ping interval")
	s.backoff = im.atLeast(s.backoff, config.MinMaxBackoff, o.path+": the reconnect interval")
	if s.backoff != nil && *s.backoff > config.MaxMaxBackoff {
		im.warn("%s: the reconnect interval is lowered to the maximum of %s", o.path, config.FormatDuration(config.MaxMaxBackoff))
		v := config.MaxMaxBackoff
		s.backoff = &v
	}
	im.ignored(o)
	return s, nil
}

func cmpOr(a, b *time.Duration) *time.Duration {
	if a != nil {
		return a
	}
	return b
}

func (im *importer) atLeast(d *time.Duration, minimum time.Duration, what string) *time.Duration {
	if d == nil || *d >= minimum {
		return d
	}
	im.warn("%s is raised to the minimum of %s", what, config.FormatDuration(minimum))
	return &minimum
}

func (im *importer) stdio(o *object, s *server, command string) error {
	args, err := o.strings("args")
	if err != nil {
		return err
	}
	env, err := o.stringMap("env")
	if err != nil {
		return err
	}
	if _, ok, _ := o.get("headers"); ok {
		im.warn("%s.headers is dropped: mcp-proxy ignores headers for stdio", o.path)
	}
	st := &config.Stdio{Command: command, Args: args, Env: env}
	if isEnvCommand(command) {
		w, ok := parseEnvWrapper(args)
		if !ok {
			im.warn("%s: the env(1) command line is not understood and is kept as it is", o.path)
		} else {
			im.unwrap(o.path, s, st, w)
		}
	}
	st.Command = convertVars(st.Command, &im.warnings, o.sub("command"))
	st.Cwd = convertVars(st.Cwd, &im.warnings, o.sub("args")+" (env -C)")
	for i := range st.Args {
		st.Args[i] = convertVars(st.Args[i], &im.warnings, fmt.Sprintf("%s.args[%d]", o.path, i))
	}
	for k, v := range st.Env {
		st.Env[k] = convertVars(v, &im.warnings, o.sub("env."+k))
	}
	if len(st.Env) == 0 {
		st.Env = nil
	}
	s.stdio = st
	return nil
}

// unwrap replaces an env(1) wrapper by the command it runs, its working directory and its
// environment.
func (im *importer) unwrap(path string, s *server, st *config.Stdio, w envWrapper) {
	st.Command, st.Args, st.Cwd = w.command, w.args, w.chdir
	if _, setsPath := w.assign["PATH"]; !strings.Contains(w.command, "/") && (w.ignoreEnv || setsPath) {
		im.warn("%s: env looked the command up in the PATH it set; mcp-gate looks it up in the gate's PATH, so write its full path if they differ", path)
	}
	if st.Env == nil {
		st.Env = map[string]string{}
	}
	if w.ignoreEnv {
		// env -i starts from nothing: neither the gate's environment nor mcp-proxy's env.
		st.Env = map[string]string{}
		st.InheritEnv = []string{}
		s.inherit = "env -i: nothing is inherited"
	}
	for _, name := range w.unset {
		delete(st.Env, name)
	}
	for k, v := range w.assign {
		st.Env[k] = v
	}
	if w.ignoreEnv || len(w.unset) == 0 {
		return
	}
	var dropped, removed []string
	inherit := append([]string(nil), config.DefaultInheritEnv...)
	for _, name := range w.unset {
		switch {
		case slices.Contains(inherit, name):
			inherit = slices.DeleteFunc(inherit, func(v string) bool { return v == name })
			removed = append(removed, name)
		case strings.HasPrefix(name, "LC_"):
			im.warn("%s: env -u %s cannot be kept, since the child inherits LC_*; set it in env if it matters", path, shownName(name))
		default:
			dropped = append(dropped, shownName(name))
		}
	}
	if len(removed) > 0 {
		st.InheritEnv = inherit
		s.inherit = "env -u " + strings.Join(removed, ", ") + ": removed from the default"
	}
	if len(dropped) > 0 {
		s.notes = append(s.notes, "env -u "+strings.Join(dropped, ", ")+
			" is dropped: a stdio child inherits only inheritEnv (default "+
			strings.Join(config.DefaultInheritEnv, " ")+") and env.")
	}
}

// varNameRE matches a valid environment variable name.
var varNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// shownName returns a variable name from the command line as comments and warnings show it: as
// it is when it is a valid name, else quoted as a Go string, so that a line break, a control
// character or a terminal escape in it stays visible and harmless in the file and on stderr.
func shownName(name string) string {
	if varNameRE.MatchString(name) {
		return name
	}
	return strconv.Quote(name)
}

func (im *importer) http(o *object, s *server, url string) error {
	url = convertVars(url, &im.warnings, o.sub("url"))
	if !strings.Contains(url, "$") {
		if err := config.CheckURL(url); err != nil {
			return fmt.Errorf("%s.url: %w", o.path, err)
		}
	}
	headers, err := o.stringMap("headers")
	if err != nil {
		return err
	}
	for k, v := range headers {
		if config.IsReservedHeader(k) {
			im.warn("%s.headers.%s is dropped: mcp-gate sets it", o.path, k)
			delete(headers, k)
			continue
		}
		headers[k] = convertVars(v, &im.warnings, o.sub("headers."+k))
	}
	if len(headers) == 0 {
		headers = nil
	}
	for _, k := range []string{"args", "env"} {
		if _, ok, _ := o.get(k); ok {
			im.warn("%s.%s is dropped: mcp-proxy ignores it for HTTP servers", o.path, k)
		}
	}
	s.http = &config.HTTP{URL: url, Headers: headers}
	return nil
}

// oauth maps a server's oauth block. Keys mcp-gate does not implement fail the import, though
// mcp-proxy ignored unknown ones: an OAuth setting silently lost could change whom the server
// trusts.
func (im *importer) oauth(o *object) (*config.OAuth, error) {
	a, err := o.object("oauth")
	if err != nil || a == nil {
		return nil, err
	}
	out := &config.OAuth{}
	for _, f := range []struct {
		key string
		to  *string
	}{
		{"clientId", &out.ClientID},
		{"clientSecret", &out.ClientSecret},
		{"redirectUri", &out.RedirectURL},
		{"authServerMetadataUrl", &out.AuthServerMetadataURL},
	} {
		v, _, err := a.str(f.key)
		if err != nil {
			return nil, err
		}
		*f.to = convertVars(v, &im.warnings, a.sub(f.key))
	}
	if out.ClientSecret != "" && out.ClientID == "" {
		return nil, fmt.Errorf("%s: clientSecret needs clientId", a.path)
	}
	if out.ClientSecret != "" && !strings.Contains(out.ClientSecret, "${") {
		im.warn("%s.clientSecret is written in the file; move it to the environment and write ${VAR}", a.path)
	}
	if out.Scopes, err = a.strings("scopes"); err != nil {
		return nil, err
	}
	if len(out.Scopes) == 0 {
		out.Scopes = nil
	}
	for i, sc := range out.Scopes {
		if sc == "" || strings.ContainsFunc(sc, func(r rune) bool { return r <= ' ' || r == '"' || r == '\\' || r > '~' }) {
			return nil, fmt.Errorf("%s[%d]: must be one scope, printable ASCII without spaces, quotes or backslashes", a.sub("scopes"), i)
		}
	}
	for k := range o.m {
		if strings.EqualFold(k, "headers") {
			if h, _ := o.m[k].(map[string]any); h != nil {
				for name := range h {
					if strings.EqualFold(name, "Authorization") {
						return nil, fmt.Errorf("%s.headers.%s: cannot be kept with oauth, which sets it", o.path, name)
					}
				}
			}
		}
	}
	if off, _, err := a.boolean("pkceDisabled"); err != nil {
		return nil, err
	} else if off {
		im.notImplemented(a.sub("pkceDisabled") + " (true): mcp-gate always uses PKCE")
	}
	for _, k := range []struct{ key, what string }{{"redirectUri", out.RedirectURL}, {"authServerMetadataUrl", out.AuthServerMetadataURL}} {
		if k.what == "" || strings.Contains(k.what, "$") {
			continue
		}
		if err := config.CheckURL(k.what); err != nil {
			return nil, fmt.Errorf("%s: %w", a.sub(k.key), err)
		}
		if !config.SecureURL(k.what) {
			return nil, fmt.Errorf("%s: must be an https URL, or http on a loopback address", a.sub(k.key))
		}
	}
	if u := o.sub("url"); !config.SecureURL(urlOf(o)) && !strings.Contains(urlOf(o), "$") {
		return nil, fmt.Errorf("%s: must be an https URL, or http on a loopback address, with oauth", u)
	}
	for _, k := range a.rest() {
		im.notImplemented(a.sub(k))
	}
	return out, nil
}

// urlOf returns a server's url, which http has checked.
func urlOf(o *object) string {
	v, _, _ := o.str("url")
	return v
}

var (
	bareVarRE = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)`)
	bracedRE  = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// convertVars rewrites the variable references that mcp-proxy expanded ($VAR and ${VAR}) as
// ${VAR}, and any other $ as $$, a literal $.
func convertVars(s string, warnings *[]string, path string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	var b strings.Builder
	literal := false
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if m := bracedRE.FindStringSubmatch(s[i:]); m != nil {
			b.WriteString(m[0])
			i += len(m[0])
			continue
		}
		if m := bareVarRE.FindStringSubmatch(s[i:]); m != nil {
			b.WriteString("${" + m[1] + "}")
			i += len(m[0])
			continue
		}
		b.WriteString("$$")
		literal = true
		i++
	}
	if literal {
		*warnings = append(*warnings, path+": a $ that is not a variable reference is kept as a literal $; mcp-proxy may have expanded it")
	}
	return b.String()
}

var wordRE = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// safeWord returns s when it is a short plain word, for quoting in a message.
func safeWord(s string) string {
	if len(s) <= 32 && wordRE.MatchString(s) {
		return s
	}
	return "unknown value"
}
