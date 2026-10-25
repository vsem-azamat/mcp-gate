// Package compare reads the catalogs of MCP servers from endpoints or snapshots and reports how two
// catalogs differ. The behaviour is specified in openspec/specs/compare/spec.md.
package compare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Catalog is one server's tools, prompts, resources and resource templates, each sorted by its
// identifier.
type Catalog struct {
	Tools             []*mcp.Tool             `json:"tools"`
	Prompts           []*mcp.Prompt           `json:"prompts"`
	Resources         []*mcp.Resource         `json:"resources"`
	ResourceTemplates []*mcp.ResourceTemplate `json:"resourceTemplates"`
}

// Kind names a list of a catalog in reports.
type Kind string

// The kinds of catalog entries.
const (
	KindTool             Kind = "tool"
	KindPrompt           Kind = "prompt"
	KindResource         Kind = "resource"
	KindResourceTemplate Kind = "resource template"
)

// entry is a catalog entry in canonical form: its identifier and its top-level fields as canonical
// JSON.
type entry struct {
	id     string
	fields map[string]json.RawMessage
}

// list is one kind of entries of a catalog, in canonical form.
type list struct {
	kind    Kind
	entries []entry
}

// lists returns the catalog's entries in canonical form, one list per kind in a fixed order.
func (c Catalog) lists() ([]list, error) {
	tools, err := canonicalList(KindTool, c.Tools, func(t *mcp.Tool) string { return t.Name })
	if err != nil {
		return nil, err
	}
	prompts, err := canonicalList(KindPrompt, c.Prompts, func(p *mcp.Prompt) string { return p.Name })
	if err != nil {
		return nil, err
	}
	resources, err := canonicalList(KindResource, c.Resources, func(r *mcp.Resource) string { return r.URI })
	if err != nil {
		return nil, err
	}
	templates, err := canonicalList(KindResourceTemplate, c.ResourceTemplates,
		func(t *mcp.ResourceTemplate) string { return t.URITemplate })
	if err != nil {
		return nil, err
	}
	return []list{tools, prompts, resources, templates}, nil
}

// canonicalList returns items in canonical form, sorted by identifier.
func canonicalList[T any](kind Kind, items []T, id func(T) string) (list, error) {
	l := list{kind: kind, entries: make([]entry, 0, len(items))}
	for _, item := range items {
		fields, err := canonicalFields(item)
		if err != nil {
			return list{}, fmt.Errorf("%s %q: %w", kind, id(item), err)
		}
		l.entries = append(l.entries, entry{id: id(item), fields: fields})
	}
	slices.SortStableFunc(l.entries, func(a, b entry) int { return strings.Compare(a.id, b.id) })
	return l, nil
}

// sort orders every list of the catalog by identifier, as snapshots store them.
func (c *Catalog) sort() {
	slices.SortStableFunc(c.Tools, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
	slices.SortStableFunc(c.Prompts, func(a, b *mcp.Prompt) int { return strings.Compare(a.Name, b.Name) })
	slices.SortStableFunc(c.Resources, func(a, b *mcp.Resource) int { return strings.Compare(a.URI, b.URI) })
	slices.SortStableFunc(c.ResourceTemplates, func(a, b *mcp.ResourceTemplate) int {
		return strings.Compare(a.URITemplate, b.URITemplate)
	})
}

// Counts is a short summary of the catalog's size, such as "3 tools, 1 prompt, 0 resources,
// 0 resource templates".
func (c Catalog) Counts() string {
	return strings.Join([]string{
		plural(len(c.Tools), "tool"),
		plural(len(c.Prompts), "prompt"),
		plural(len(c.Resources), "resource"),
		plural(len(c.ResourceTemplates), "resource template"),
	}, ", ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// canonicalFields encodes v as JSON and returns its top-level fields, each in canonical form.
func canonicalFields(v any) (map[string]json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	fields := make(map[string]json.RawMessage, len(raw))
	for k, r := range raw {
		c, err := canonical(r)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", k, err)
		}
		fields[k] = c
	}
	return fields, nil
}

// canonical re-encodes a JSON value with object keys sorted, no insignificant whitespace and no
// HTML escaping. Numbers keep the form they have in r; values decoded by the SDK reach it already
// as float64.
func canonical(r json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(r))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
