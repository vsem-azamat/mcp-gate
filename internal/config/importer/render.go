package importer

import (
	"bytes"
	"sort"
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
	servers := mapping()
	for _, s := range d.servers {
		node := s.node()
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

func (s *server) node() *yaml.Node {
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
