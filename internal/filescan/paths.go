package filescan

import (
	"cmp"
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

// downloadedToRE finds "downloaded to <path>" and the like in text. An unquoted path may hold
// spaces, so it is matched only as far as its first word; see unquotedPath.
var downloadedToRE = regexp.MustCompile(`(?i)(?:downloaded|saved|written)\s+to\s+(?:"([^"\r\n]+)"|'([^'\r\n]+)'|(/[^\s"'<>]+))`)

const (
	// maxPathWords bounds the words of an unquoted path tried, so a long line costs little.
	maxPathWords = 16
	// maxTailBytes bounds the rest of a line an unquoted path is looked for in.
	maxTailBytes = 4096
	// maxMentions bounds the "downloaded to" mentions of one call.
	maxMentions = 64
	// maxLookups bounds the file lookups of one call's unquoted paths.
	maxLookups = maxMentions * maxPathWords
)

// unquotedPath returns the path an unquoted "downloaded to" names in tail, the rest of its line:
// the longest of its first maxPathWords words, trailing punctuation dropped, that isFile
// accepts, or the first word when none is accepted or isFile is nil.
func unquotedPath(tail string, isFile func(string) bool) string {
	const space = "\t\n\f\r " // what \s matches in downloadedToRE
	tail = strings.TrimRight(tail, space)
	var ends []int // the end of each word, the last being the end of the tail
	for i := 1; i < len(tail) && len(ends) < maxPathWords-1; i++ {
		if strings.IndexByte(space, tail[i]) >= 0 && strings.IndexByte(space, tail[i-1]) < 0 {
			ends = append(ends, i)
		}
	}
	if len(ends) < maxPathWords-1 {
		ends = append(ends, len(tail))
	}
	if isFile != nil {
		for i := len(ends) - 1; i > 0; i-- {
			if p := strings.TrimRight(tail[:ends[i]], ".,;"); isFile(p) {
				return p
			}
		}
	}
	return tail[:ends[0]]
}

// candidate is an absolute path a file tool's call names.
type candidate struct {
	path string // cleaned
	raw  string // as written, for withholding
	// fromArguments is set when only the arguments name it, not the result.
	fromArguments bool
}

// candidates collects the absolute paths a file tool reported in its result (path members of
// structured content and of JSON text at any depth, file:// URIs, "downloaded to" in text) or
// that its arguments name (an output path the caller chose). isFile, which may be nil, tells
// where an unquoted path with spaces ends. The budget is per call: collecting stops, and
// overflow is set, as soon as more than maxCandidates paths are found, the texts hold more than
// maxMentions "downloaded to" mentions in all, or isFile would be called more than maxLookups
// times, so that the work stays bounded however the result is split into content items.
func candidates(args map[string]any, res *mcp.CallToolResult, isFile func(string) bool) (out []candidate, overflow bool) {
	fromArguments := false
	mentions, lookups := 0, 0
	var lookup func(string) bool
	if isFile != nil {
		lookup = func(path string) bool {
			if lookups >= maxLookups {
				overflow = true
				return false
			}
			lookups++
			return isFile(path)
		}
	}
	full := func() bool { return overflow || len(out) > maxCandidates }
	add := func(raw string) {
		if full() {
			return
		}
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
		if depth > maxDepth || full() {
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
		if full() {
			break
		}
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
		matches := downloadedToRE.FindAllStringSubmatchIndex(text, maxMentions+1-mentions)
		if mentions += len(matches); mentions > maxMentions {
			overflow = true
		}
		for _, m := range matches {
			if full() {
				break
			}
			switch {
			case m[2] >= 0:
				add(text[m[2]:m[3]])
			case m[4] >= 0:
				add(text[m[4]:m[5]])
			case m[6] >= 0:
				// The rest of the line, up to a quote or angle bracket.
				tail := text[m[6]:min(len(text), m[6]+maxTailBytes)]
				if end := strings.IndexAny(tail, "\r\n\"'<>"); end >= 0 {
					tail = tail[:end]
				}
				add(unquotedPath(tail, lookup))
			}
		}
	}
	fromArguments = true
	if args != nil {
		walk("", args, 0)
	}
	return out, full()
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

// contentMeta returns the _meta objects of a content block: its own and, for an embedded
// resource, the resource's.
func contentMeta(c mcp.Content) []map[string]any {
	switch v := c.(type) {
	case *mcp.TextContent:
		if v != nil {
			return []map[string]any{v.Meta}
		}
	case *mcp.ImageContent:
		if v != nil {
			return []map[string]any{v.Meta}
		}
	case *mcp.AudioContent:
		if v != nil {
			return []map[string]any{v.Meta}
		}
	case *mcp.ResourceLink:
		if v != nil {
			return []map[string]any{v.Meta}
		}
	case *mcp.EmbeddedResource:
		if v != nil {
			m := []map[string]any{v.Meta}
			if v.Resource != nil {
				m = append(m, v.Resource.Meta)
			}
			return m
		}
	}
	return nil
}

// mention is a withheld file: the forms of its path that mark a mention of it, and what
// replaces one.
type mention struct {
	paths          []string
	marker, notice string
}

// withhold returns redacted with every mention of a file in files removed: a content block whose
// text, URI or _meta names one of its paths, or whose block in downstream (the result redacted
// was made from, block for block) does, becomes its notice, and a string in structured content
// or in the result's _meta that names one becomes its marker (a string, so that an output schema
// requiring the member still validates). Where a block or string names several files, it gets
// the notice or marker of one of them. Neither result is modified.
func withhold(downstream, redacted *mcp.CallToolResult, files []mention) *mcp.CallToolResult {
	// mentioned returns the file text names, or nil.
	mentioned := func(text string) *mention {
		if text == "" {
			return nil
		}
		for i := range files {
			for _, p := range files[i].paths {
				if p != "" && strings.Contains(text, p) {
					return &files[i]
				}
			}
		}
		return nil
	}
	// Unlike the search for paths, this walk has no depth limit: a mention anywhere is removed.
	var replace func(value any) (any, *mention)
	replace = func(value any) (any, *mention) {
		var first *mention
		switch v := value.(type) {
		case map[string]any:
			var copied map[string]any
			for k, item := range v {
				if updated, m := replace(item); m != nil {
					if copied == nil {
						copied = make(map[string]any, len(v))
						for kk, vv := range v {
							copied[kk] = vv
						}
					}
					copied[k] = updated
					first = cmp.Or(first, m)
				}
			}
			if copied == nil {
				return v, nil
			}
			return copied, first
		case []any:
			var copied []any
			for i, item := range v {
				if updated, m := replace(item); m != nil {
					if copied == nil {
						copied = slices.Clone(v)
					}
					copied[i] = updated
					first = cmp.Or(first, m)
				}
			}
			if copied == nil {
				return v, nil
			}
			return copied, first
		case string:
			if m := mentioned(v); m != nil {
				return m.marker, m
			}
		}
		return value, nil
	}
	blockMentions := func(c mcp.Content) *mention {
		embedded := ""
		if e, ok := c.(*mcp.EmbeddedResource); ok && e != nil && e.Resource != nil {
			embedded = e.Resource.Text
		}
		m := cmp.Or(mentioned(contentText(c)), mentioned(contentURI(c)), mentioned(embedded))
		for _, meta := range contentMeta(c) {
			if _, mm := replace(meta); mm != nil {
				m = cmp.Or(m, mm)
			}
		}
		return m
	}
	out := *redacted
	out.Content = slices.Clone(redacted.Content)
	aligned := len(downstream.Content) == len(redacted.Content)
	for i, c := range out.Content {
		m := blockMentions(c)
		if aligned {
			m = cmp.Or(m, blockMentions(downstream.Content[i]))
		}
		if m != nil {
			out.Content[i] = &mcp.TextContent{Text: m.notice}
		}
	}
	if redacted.StructuredContent != nil {
		if updated, m := replace(redacted.StructuredContent); m != nil {
			out.StructuredContent = updated
		}
	}
	if redacted.Meta != nil {
		if updated, m := replace(map[string]any(redacted.Meta)); m != nil {
			out.Meta = updated.(map[string]any) //nolint:forcetypeassert // replace returns a map for a map
		}
	}
	return &out
}
