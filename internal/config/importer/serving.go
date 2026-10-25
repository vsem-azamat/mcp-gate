package importer

import (
	"fmt"
	"net/url"
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
	if out.redact, err = im.redactBlock(o); err != nil {
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

// escrowKeys belong to the escrow and file scanning, which this build does not implement.
var escrowKeys = []string{"escrowTTL", "escrowMaxEntries", "fileTools", "fileRoots", "fileMaxBytes"}

func (im *importer) redactBlock(o *object) (*redactBlock, error) {
	r, err := o.object("redact")
	if err != nil || r == nil {
		return nil, err
	}
	b := &redactBlock{present: true}
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
	for _, k := range escrowKeys {
		v, ok, err := r.get(k)
		if err != nil {
			return nil, err
		}
		if list, isList := v.([]any); ok && (!isList || len(list) > 0) {
			im.notImplemented(r.sub(k))
		}
	}
	im.ignored(r)
	return b, nil
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
	case !r.enabled && (r.highEntropy || len(r.disableRules) > 0):
		im.warn("%s: redact has settings but enabled is false, so they are dropped", path)
		s.redact = redactBlock{present: true}
	default:
		s.redact = *r
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
