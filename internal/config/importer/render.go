package importer

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

const header = "Written by mcp-gate import from an mcp-proxy config. Review the comments, then run mcp-gate check."

// render writes the document as YAML. Keys that are not implemented are listed as comments with
// config.PartialMarker: above their server, or at the top for the others.
func (d *document) render(unimplemented []string) ([]byte, error) {
	perServer := map[string][]string{}
	top := []string{header}
	top = append(top, d.notes...)
	for _, key := range unimplemented {
		placed := false
		for _, s := range d.servers {
			prefix := "mcpServers." + s.name
			if strings.HasPrefix(key, prefix+".") {
				perServer[s.name] = append(perServer[s.name], config.PartialMarker+": "+key)
				placed = true
				break
			}
		}
		if !placed {
			top = append(top, config.PartialMarker+": "+key)
		}
	}

	root := mapping()
	add(root, "version", scalar("1", "!!int"), "")
	root.Content[0].HeadComment = comment(top)
	if d.name != "" {
		add(root, "name", str(d.name), "")
	}
	if d.addr != "" {
		l := mapping()
		add(l, "addr", str(d.addr), "mcp-proxy mcpProxy.addr")
		add(root, "listen", l, "")
	}
	if d.grace != nil {
		add(root, "startupGracePeriod", str(config.FormatDuration(*d.grace)), "")
	}
	if len(d.tokens) > 0 {
		a := mapping()
		add(a, "tokens", d.tokenMap(d.tokens), "")
		add(root, "auth", a, "")
	}
	if d.escrowTTL != nil || d.maxEntries > 0 {
		e := mapping()
		if d.escrowTTL != nil {
			add(e, "ttl", str(config.FormatDuration(*d.escrowTTL)), "mcp-proxy mcpProxy.options.redact.escrowTTL")
		}
		if d.maxEntries > 0 {
			add(e, "maxEntries", scalar(strconv.FormatInt(d.maxEntries, 10), "!!int"), "")
		}
		add(root, "escrow", e, "")
	}
	servers := mapping()
	for _, s := range d.servers {
		node := s.node(d)
		add(servers, s.name, node, "")
		key := servers.Content[len(servers.Content)-2]
		key.HeadComment = comment(append(append([]string(nil), s.notes...), perServer[s.name]...))
	}
	add(root, "servers", servers, "")

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// tokenMap writes tokens by name.
func (d *document) tokenMap(tokens []string) *yaml.Node {
	m := map[string]string{}
	for _, v := range tokens {
		m[d.names[v]] = v
	}
	return strMap(m)
}

func (s *server) node(d *document) *yaml.Node {
	n := mapping()
	if st := s.stdio; st != nil {
		m := mapping()
		add(m, "command", str(st.Command), "")
		if len(st.Args) > 0 {
			add(m, "args", strList(st.Args), "")
		}
		if st.Cwd != "" {
			add(m, "cwd", str(st.Cwd), "")
		}
		if len(st.Env) > 0 {
			add(m, "env", strMap(st.Env), "")
		}
		if st.InheritEnv != nil {
			add(m, "inheritEnv", strList(st.InheritEnv), "")
			m.Content[len(m.Content)-2].HeadComment = comment(nonEmpty(s.inherit))
		}
		add(n, "stdio", m, "")
	}
	if h := s.http; h != nil {
		m := mapping()
		add(m, "url", str(h.URL), "")
		if len(h.Headers) > 0 {
			add(m, "headers", strMap(h.Headers), "")
		}
		add(n, "http", m, "")
	}
	add(n, "callTimeout", str(config.FormatDuration(s.timeout)), s.tNote)
	if s.probe != nil {
		add(n, "probeInterval", str(config.FormatDuration(*s.probe)), "mcp-proxy pingInterval")
	}
	if s.backoff != nil {
		r := mapping()
		add(r, "maxBackoff", str(config.FormatDuration(*s.backoff)), "mcp-proxy reconnectInterval")
		add(n, "restart", r, "")
	}
	if s.disabled {
		add(n, "disabled", scalar("true", "!!bool"), "")
	}
	for kind, f := range s.filters {
		if f == nil {
			continue
		}
		m := mapping()
		if f.Allow != nil {
			add(m, "allow", strList(f.Allow), "")
		} else {
			add(m, "deny", strList(f.Deny), "")
		}
		m.Style = yaml.FlowStyle
		add(n, filterWords[kind], m, s.fNotes[kind])
	}
	switch {
	case s.public != "":
		a := mapping()
		add(a, "public", scalar("true", "!!bool"), s.public)
		add(n, "auth", a, "")
	case s.tokens != nil:
		a := mapping()
		add(a, "inherit", scalar("false", "!!bool"), "mcp-proxy: per-server authTokens replace the global ones")
		add(a, "tokens", d.tokenMap(s.tokens), "")
		add(n, "auth", a, "")
	}
	if s.requests {
		l := mapping()
		add(l, "requests", scalar("true", "!!bool"), "mcp-proxy logEnabled")
		add(n, "log", l, "")
	}
	r := mapping()
	switch {
	case !s.redact.present:
		add(r, "enabled", scalar("false", "!!bool"), "mcp-proxy did not redact this server; consider turning it on")
	case !s.redact.enabled:
		add(r, "enabled", scalar("false", "!!bool"), "")
	default:
		add(r, "ru", scalar("true", "!!bool"), "mcp-proxy always ran the Russian rules")
		if s.redact.highEntropy {
			add(r, "highEntropy", scalar("true", "!!bool"), "")
		}
		if len(s.redact.disableRules) > 0 {
			add(r, "disableRules", strList(s.redact.disableRules), "")
		}
		if s.redact.escrowTTL != nil {
			add(r, "escrowTTL", str(config.FormatDuration(*s.redact.escrowTTL)), "")
		}
		if f := s.redact.files; f != nil {
			m := mapping()
			tools, roots := strList(f.Tools), strList(f.Roots)
			tools.Style, roots.Style = yaml.FlowStyle, yaml.FlowStyle
			add(m, "tools", tools, "")
			add(m, "roots", roots, "")
			if f.MaxBytes != nil {
				add(m, "maxBytes", str(f.MaxBytes.String()), "")
			}
			add(r, "files", m, "")
		}
	}
	add(n, "redact", r, "")
	return n
}

func mapping() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }

func scalar(v, tag string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: v} }

func str(v string) *yaml.Node { return scalar(v, "!!str") }

func strList(vs []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if len(vs) == 0 {
		n.Style = yaml.FlowStyle
	}
	for _, v := range vs {
		n.Content = append(n.Content, str(v))
	}
	return n
}

func strMap(m map[string]string) *yaml.Node {
	n := mapping()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(n, k, str(m[k]), "")
	}
	return n
}

func add(m *yaml.Node, key string, value *yaml.Node, lineComment string) {
	if lineComment != "" {
		value.LineComment = "# " + lineComment
	}
	m.Content = append(m.Content, str(key), value)
}

func comment(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return "# " + strings.Join(lines, "\n# ")
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
