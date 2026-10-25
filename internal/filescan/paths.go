package filescan

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxDepth bounds the walk of structured values.
const maxDepth = 8

// pathKeys are result and argument members that name a downloaded file.
var pathKeys = []string{"path", "file_path", "filePath", "outputPath", "output_path", "localPath", "local_path", "savedTo", "saved_to"}

// downloadedToRE finds "downloaded to <path>" and the like in text.
var downloadedToRE = regexp.MustCompile(`(?i)(?:downloaded|saved|written)\s+to\s+(?:"([^"\r\n]+)"|'([^'\r\n]+)'|(/[^\s"'<>]+))`)

// candidate is an absolute path a file tool's call names.
type candidate struct {
	path string // cleaned
	raw  string // as written, for withholding
	// fromArguments is set when only the arguments name it, not the result.
	fromArguments bool
}

// candidates collects the absolute paths a file tool reported in its result (path members of
// structured content and of JSON text at any depth, file:// URIs, "downloaded to" in text) or
// that its arguments name (an output path the caller chose).
func candidates(args map[string]any, res *mcp.CallToolResult) []candidate {
	var out []candidate
	fromArguments := false
	add := func(raw string) {
		c := strings.TrimSpace(raw)
		if rest, ok := strings.CutPrefix(c, "file://"); ok {
			unescaped, err := url.PathUnescape(rest)
			if err != nil {
				return
			}
			c = unescaped
		}
		c = strings.TrimRight(c, ".,;")
		if !filepath.IsAbs(c) {
			return
		}
		c = filepath.Clean(c)
		for i := range out {
			if out[i].path == c {
				// Reported by the tool as well: not the caller's alone.
				out[i].fromArguments = out[i].fromArguments && fromArguments
				return
			}
		}
		out = append(out, candidate{path: c, raw: strings.TrimRight(strings.TrimSpace(raw), ".,;"), fromArguments: fromArguments})
	}
	var walk func(key string, value any, depth int)
	walk = func(key string, value any, depth int) {
		if depth > maxDepth {
			return
		}
		switch v := value.(type) {
		case map[string]any:
			for k, item := range v {
				walk(k, item, depth+1)
			}
		case []any:
			for _, item := range v {
				walk(key, item, depth+1)
			}
		case string:
			if slices.Contains(pathKeys, key) || strings.HasPrefix(v, "file://") {
				add(v)
			}
		}
	}
	if res.StructuredContent != nil {
		walk("", res.StructuredContent, 0)
	}
	for _, c := range res.Content {
		if uri := contentURI(c); uri != "" {
			add(uri)
		}
		text := contentText(c)
		if text == "" {
			continue
		}
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) == nil {
			walk("", decoded, 0)
		}
		for _, m := range downloadedToRE.FindAllStringSubmatch(text, -1) {
			for _, group := range m[1:] {
				if group != "" {
					add(group)
					break
				}
			}
		}
	}
	fromArguments = true
	if args != nil {
		walk("", args, 0)
	}
	return out
}

func contentText(c mcp.Content) string {
	if t, ok := c.(*mcp.TextContent); ok && t != nil {
		return t.Text
	}
	return ""
}

func contentURI(c mcp.Content) string {
	switch v := c.(type) {
	case *mcp.ResourceLink:
		if v != nil {
			return v.URI
		}
	case *mcp.EmbeddedResource:
		if v != nil && v.Resource != nil {
			return v.Resource.URI
		}
	}
	return ""
}

// withhold returns res with every mention of a file removed: a content block whose text or URI
// names one of paths becomes notice, and a string in structured content that names one becomes
// marker (a string, so that an output schema requiring the member still validates). res is not
// modified.
func withhold(res *mcp.CallToolResult, paths []string, marker, notice string) *mcp.CallToolResult {
	mentions := func(text string) bool {
		for _, p := range paths {
			if p != "" && strings.Contains(text, p) {
				return true
			}
		}
		return false
	}
	out := *res
	out.Content = slices.Clone(res.Content)
	for i, c := range out.Content {
		embedded := ""
		if e, ok := c.(*mcp.EmbeddedResource); ok && e != nil && e.Resource != nil {
			embedded = e.Resource.Text
		}
		if mentions(contentText(c)) || mentions(contentURI(c)) || mentions(embedded) {
			out.Content[i] = &mcp.TextContent{Text: notice}
		}
	}
	// Unlike the search for paths, this walk has no depth limit: a mention anywhere is removed.
	var replace func(value any) (any, bool)
	replace = func(value any) (any, bool) {
		switch v := value.(type) {
		case map[string]any:
			var copied map[string]any
			for k, item := range v {
				if updated, changed := replace(item); changed {
					if copied == nil {
						copied = make(map[string]any, len(v))
						for kk, vv := range v {
							copied[kk] = vv
						}
					}
					copied[k] = updated
				}
			}
			if copied == nil {
				return v, false
			}
			return copied, true
		case []any:
			var copied []any
			for i, item := range v {
				if updated, changed := replace(item); changed {
					if copied == nil {
						copied = slices.Clone(v)
					}
					copied[i] = updated
				}
			}
			if copied == nil {
				return v, false
			}
			return copied, true
		case string:
			if mentions(v) {
				return marker, true
			}
		}
		return value, false
	}
	if res.StructuredContent != nil {
		if updated, changed := replace(res.StructuredContent); changed {
			out.StructuredContent = updated
		}
	}
	return &out
}
