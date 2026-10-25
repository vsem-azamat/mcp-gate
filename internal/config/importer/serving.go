package importer

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// Filter kinds, in the order of server.filters.
const (
	filterTools = iota
	filterPrompts
	filterResources
)

var filterKeys = [3]string{"toolFilter", "promptFilter", "resourceFilter"}

// filterWords name what each filter selects, for comments.
var filterWords = [3]string{"tools", "prompts", "resources"}

// listen maps mcpProxy.addr, baseURL and startupGracePeriod.
func (im *importer) listen(p *object, doc *document) error {
	addr, ok, err := p.str("addr")
	if err != nil {
		return err
	}
	if ok {
		doc.addr = addr
	}
	base, ok, err := p.str("baseURL")
	if err != nil {
		return err
	}
	if ok {
		u, err := url.Parse(base)
		switch {
		case err != nil:
			return fmt.Errorf("%s: is not a valid URL", p.sub("baseURL"))
		case u.Path == "" || u.Path == "/":
			doc.notes = append(doc.notes, "mcpProxy.baseURL is dropped: mcp-gate serves each server at /<name>/mcp.")
		default:
			im.notImplemented(p.sub("baseURL") + " (with a path): mcp-gate serves each server at /<name>/mcp")
		}
	}
	grace, ok, err := p.duration("startupGracePeriod")
	if err != nil {
		return err
	}
	if ok && grace > 0 {
		doc.grace = &grace
	}
	return nil
}

// serving reads the options that the upstream side implements: tokens, filters, logging and
// redaction.
func (im *importer) serving(o *object, global bool, out *options) error {
	tokens, err := o.strings("authTokens")
	if err != nil {
		return err
	}
	for i, tok := range tokens {
		if strings.TrimSpace(tok) == "" {
			return fmt.Errorf("%s.authTokens[%d]: cannot be empty", o.path, i)
		}
		tokens[i] = convertVars(tok, &im.warnings, fmt.Sprintf("%s.authTokens[%d]", o.path, i))
	}
	out.tokens = tokens
	if v, ok, err := o.boolean("logEnabled"); err != nil {
		return err
	} else if ok {
		out.logEnabled = &v
	}
	if out.redact, err = im.redactBlock(o, global); err != nil {
		return err
	}
	for kind, key := range filterKeys {
		f, err := o.object(key)
		if err != nil {
			return err
		}
		if f == nil {
			continue
		}
		if global {
			im.warn("%s.%s is dropped: mcp-proxy does not apply a global filter to servers", o.path, key)
			_, _, _ = f.get("mode")
			_, _, _ = f.get("list")
			continue
		}
		if out.filters[kind], out.fNotes[kind], err = im.filter(f, kind); err != nil {
			return err
		}
		if out.filters[kind] == nil && out.fNotes[kind] != "" {
			out.notes = append(out.notes, out.fNotes[kind])
			out.fNotes[kind] = ""
		}
	}
	return nil
}

// filter maps one mcp-proxy filter. A filter that filters nothing is dropped, with a note.
func (im *importer) filter(f *object, kind int) (*config.Filter, string, error) {
	mode, _, err := f.str("mode")
	if err != nil {
		return nil, "", err
	}
	list, err := f.strings("list")
	if err != nil {
		return nil, "", err
	}
	im.ignored(f)
	for i, v := range list {
		if strings.TrimSpace(v) == "" {
			return nil, "", fmt.Errorf("%s.list[%d]: cannot be empty", f.path, i)
		}
	}
	if list == nil {
		list = []string{}
	}
	switch strings.ToLower(mode) {
	case "allow":
		switch {
		case len(list) > 0:
			return &config.Filter{Allow: list}, "", nil
		case kind == filterTools:
			return nil, f.path + " is dropped: an empty allow list means no tool filter in mcp-proxy.", nil
		default:
			return &config.Filter{Allow: list}, "an empty allow list exposes no " + filterWords[kind] + ", as in mcp-proxy", nil
		}
	case "block":
		if len(list) == 0 {
			return nil, f.path + " is dropped: an empty block list filters nothing.", nil
		}
		return &config.Filter{Deny: list}, "mcp-proxy mode block", nil
	default:
		return nil, "", fmt.Errorf("%s.mode: must be allow or block", f.path)
	}
}

func (im *importer) redactBlock(o *object, global bool) (*redactBlock, error) {
	r, err := o.object("redact")
	if err != nil || r == nil {
		return nil, err
	}
	b := &redactBlock{present: true, path: r.path}
	if b.enabled, _, err = r.boolean("enabled"); err != nil {
		return nil, err
	}
	if b.highEntropy, _, err = r.boolean("highEntropy"); err != nil {
		return nil, err
	}
	if b.disableRules, err = r.strings("disableRules"); err != nil {
		return nil, err
	}
	for i, kind := range b.disableRules {
		if !slices.Contains(redact.Kinds(), kind) {
			return nil, fmt.Errorf("%s.disableRules[%d]: not a rule mcp-gate knows (known: %s)", r.path, i, strings.Join(redact.Kinds(), ", "))
		}
	}
	if d, ok, err := r.duration("escrowTTL"); err != nil {
		return nil, err
	} else if ok && d > 0 {
		b.escrowTTL = &d
	}
	if err := im.maxEntries(r, global, b); err != nil {
		return nil, err
	}
	if b.files, err = im.files(r); err != nil {
		return nil, err
	}
	im.ignored(r)
	return b, nil
}

// maxEntries reads escrowMaxEntries, which mcp-proxy reads only from the global block.
func (im *importer) maxEntries(r *object, global bool, b *redactBlock) error {
	n, ok, err := r.integer("escrowMaxEntries")
	switch {
	case err != nil:
		return err
	case !ok || n == 0:
		return nil
	case n < 0:
		return fmt.Errorf("%s: cannot be negative", r.sub("escrowMaxEntries"))
	case !global:
		im.warn("%s is dropped: mcp-proxy reads it only from mcpProxy.options.redact", r.sub("escrowMaxEntries"))
		return nil
	case n > config.MaxEscrowEntries:
		im.warn("%s is lowered to the maximum of %d", r.sub("escrowMaxEntries"), config.MaxEscrowEntries)
		n = config.MaxEscrowEntries
	}
	b.maxEntries = n
	return nil
}

// files reads fileTools, fileRoots and fileMaxBytes. mcp-proxy scanned files only under roots
// that are absolute paths, so file tools without such a root scanned nothing and are dropped.
func (im *importer) files(r *object) (*config.Files, error) {
	tools, err := r.strings("fileTools")
	if err != nil {
		return nil, err
	}
	roots, err := r.strings("fileRoots")
	if err != nil {
		return nil, err
	}
	maxBytes, hasMax, err := r.integer("fileMaxBytes")
	if err != nil {
		return nil, err
	}
	if maxBytes < 0 {
		return nil, fmt.Errorf("%s: cannot be negative", r.sub("fileMaxBytes"))
	}
	var kept []string
	for i, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) == "/" {
			im.warn("%s.fileRoots[%d] is dropped: mcp-proxy scanned only under absolute roots, and mcp-gate does not take /", r.path, i)
			continue
		}
		kept = append(kept, filepath.Clean(root))
	}
	switch {
	case len(tools) == 0 && len(kept) == 0:
		return nil, nil
	case len(tools) == 0:
		im.warn("%s.fileRoots is dropped: no fileTools, so no file is scanned", r.path)
		return nil, nil
	case len(kept) == 0:
		im.warn("%s.fileTools is dropped: without a usable fileRoots entry, mcp-proxy scanned no file", r.path)
		return nil, nil
	}
	for i, t := range tools {
		if strings.TrimSpace(t) == "" {
			return nil, fmt.Errorf("%s.fileTools[%d]: cannot be empty", r.path, i)
		}
	}
	var unique []string
	for _, t := range tools {
		if !slices.Contains(unique, t) {
			unique = append(unique, t)
		}
	}
	f := &config.Files{Tools: unique, Roots: slices.Compact(kept)}
	if hasMax && maxBytes > 0 {
		v := config.ByteSize(min(max(maxBytes, config.MinFileMaxBytes), config.MaxFileMaxBytes))
		if int64(v) != maxBytes {
			im.warn("%s.fileMaxBytes is moved into the range mcp-gate takes, %s to %s", r.path, config.ByteSize(config.MinFileMaxBytes), config.ByteSize(config.MaxFileMaxBytes))
		}
		f.MaxBytes = &v
	}
	return f, nil
}

// applyServing sets the serving keys of s from its options and the proxy's, which it inherits
// as mcp-proxy did: tokens, logEnabled and redact when it has none of its own.
func (im *importer) applyServing(path string, s *server, local, global *options) {
	s.filters, s.fNotes = local.filters, local.fNotes
	switch {
	case local.tokens != nil && len(local.tokens) == 0:
		s.public = "mcp-proxy served it without a token: its authTokens list is empty"
	case local.tokens != nil && !sameSet(local.tokens, global.tokens):
		s.tokens = local.tokens
	case local.tokens == nil && len(global.tokens) == 0:
		s.public = "mcp-proxy served it without a token"
	}
	logEnabled := local.logEnabled
	if logEnabled == nil {
		logEnabled = global.logEnabled
	}
	s.requests = logEnabled != nil && *logEnabled
	r := local.redact
	if r == nil {
		r = global.redact
	}
	switch {
	case r == nil:
		s.redact = redactBlock{present: false}
	case !r.enabled && (r.highEntropy || len(r.disableRules) > 0 || r.files != nil || (r == local.redact && r.escrowTTL != nil)):
		im.warn("%s: redact has settings but enabled is false, so they are dropped", path)
		s.redact = redactBlock{present: true}
	default:
		s.redact = *r
		if r != local.redact {
			// The global escrowTTL is escrow.ttl; a server inheriting the block needs no copy.
			s.redact.escrowTTL = nil
		}
	}
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

var tokenVarRE = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// nameTokens names every client token. A token read from a variable is named after the variable
// with the prefix all token variables share removed, lower-cased: ${HUB_TOKEN_LAPTOP} and
// ${HUB_TOKEN_PHONE} become laptop and phone. When that leaves a name empty, invalid or taken
// twice, or a token is written out, the tokens are named token1, token2 and so on.
func (im *importer) nameTokens(doc *document) {
	var order []string
	seen := map[string]bool{}
	addAll := func(list []string) {
		for _, v := range list {
			if !seen[v] {
				seen[v] = true
				order = append(order, v)
			}
		}
	}
	addAll(doc.tokens)
	for _, s := range doc.servers {
		addAll(s.tokens)
	}
	doc.names = map[string]string{}
	if len(order) == 0 {
		return
	}
	vars := make([]string, 0, len(order))
	literal := false
	for _, v := range order {
		m := tokenVarRE.FindStringSubmatch(v)
		if m == nil {
			literal = true
			continue
		}
		vars = append(vars, m[1])
	}
	if literal {
		im.warn("a client token is written in the config; move it to the environment and reference it as ${NAME}")
	}
	prefix := ""
	if len(vars) > 1 {
		prefix = commonPrefix(vars)
		if i := strings.LastIndex(prefix, "_"); i >= 0 {
			prefix = prefix[:i+1]
		} else {
			prefix = ""
		}
	}
	derived := map[string]string{}
	taken := map[string]bool{}
	ok := !literal
	for _, v := range order {
		if !ok {
			break
		}
		name := strings.ToLower(strings.TrimPrefix(tokenVarRE.FindStringSubmatch(v)[1], prefix))
		if !config.TokenNameRE.MatchString(name) || taken[name] {
			ok = false
			break
		}
		taken[name] = true
		derived[v] = name
	}
	for i, v := range order {
		if ok {
			doc.names[v] = derived[v]
		} else {
			doc.names[v] = "token" + strconv.Itoa(i+1)
		}
	}
}

func commonPrefix(vs []string) string {
	p := vs[0]
	for _, v := range vs[1:] {
		for !strings.HasPrefix(v, p) {
			p = p[:len(p)-1]
		}
	}
	return p
}
