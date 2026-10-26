package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"
)

// maxJSONDepth bounds how far JSON nested inside JSON strings is followed.
const maxJSONDepth = 5

// minSecretNumberLength is the length a number under a secret member needs to be replaced; a
// shorter one ("pin": 1) is a flag or a count.
const minSecretNumberLength = 3

// nestedSafeKeys are members inside a secret object that describe the secret rather than hold
// it ({"token": {"type": "Bearer", "expires_in": 3600}}).
var nestedSafeKeys = []string{
	"user", "username", "login", "email", "type", "tokentype", "scope", "scopes",
	"expires", "expiresin", "expiresat", "expiry", "issuer", "name", "id", "kind",
}

func looksLikeJSON(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < 2 {
		return false
	}
	first, last := trimmed[0], trimmed[len(trimmed)-1]
	return ((first == '{' && last == '}') || (first == '[' && last == ']')) && json.Valid([]byte(trimmed))
}

// redactJSONValue redacts one decoded JSON string value. secretKind is set when the value sits
// under a secret member (directly or nested): it is then replaced as a whole or, when it is
// itself JSON, rewritten with everything inside treated as secret.
func (e *Engine) redactJSONValue(secretKind, value string, r Replacer, depth int) string {
	if secretKind != "" && !e.disabled[secretKind] {
		if depth < maxJSONDepth && looksLikeJSON(value) {
			if out, err := e.rewriteJSON([]byte(value), r, depth+1, secretKind); err == nil {
				return string(out)
			}
		}
		if !isPlaceholderValue(value) {
			return r.Replace(Finding{Kind: secretKind, Value: value})
		}
		return value
	}
	return e.redactString(value, r, depth)
}

// namesBudgetFallbacks counts the objects whose names were kept apart from the replacements
// only, because the scan budget was spent; tests read it.
var namesBudgetFallbacks atomic.Int64

// The bytes objectNames may read in one document: namesScanFactor times its size, plus
// namesScanSlack.
const (
	namesScanFactor = 8
	namesScanSlack  = 1 << 20
)

// errBadString reports a string literal that does not decode; it cannot happen for valid JSON.
var errBadString = errors.New("redact: undecodable JSON string")

// frame is an open object or array while rewriteJSON walks a document.
type frame struct {
	object    bool
	expectKey bool
	key       string
	// inherited is the secret kind of an enclosing secret member: every value below it is
	// secret unless its own name says otherwise.
	inherited string
	// start is the offset of an object's opening brace; taken holds the names of its
	// members as written and those given to replaced names, once a name is replaced.
	start int
	taken map[string]bool
	// next is the suffix to try next for each replacement, so that many names replaced
	// alike cost linear time.
	next map[string]int
}

// rewriteJSON rewrites the string values of data, which is valid JSON. inherited is the secret
// kind of the member the whole document sits under, or "" at the top level.
func (e *Engine) rewriteJSON(data []byte, r Replacer, depth int, inherited string) ([]byte, error) {
	stack := make([]frame, 0, 8)
	// scanBudget bounds the bytes objectNames reads, which nested objects with replaced names
	// would otherwise make quadratic.
	scanBudget := namesScanFactor*len(data) + namesScanSlack
	cleanNames := map[string]struct{}{}
	// secretNames remembers the shape of the names met under secret members.
	secretNames := map[string]nameShape{}
	// heads maps the offset of a string literal to the end of the rest of a token split from the
	// string before it (see splitAfter).
	var heads map[int]int
	currentKey := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1].key
	}
	// secretKind is the kind of the value at the current position, or "".
	secretKind := func() string {
		if len(stack) == 0 {
			return inherited
		}
		top := stack[len(stack)-1]
		return memberKind(top.key, top.inherited)
	}
	var out bytes.Buffer
	last := 0
	for i := 0; i < len(data); {
		switch data[i] {
		case '{':
			stack = append(stack, frame{object: true, expectKey: true, inherited: secretKind(), start: i})
			i++
		case '[':
			// Elements of an array inherit the member name it is stored under.
			stack = append(stack, frame{key: currentKey(), inherited: secretKind()})
			i++
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
			i++
		case ':':
			if len(stack) > 0 {
				stack[len(stack)-1].expectKey = false
			}
			i++
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			// A number under a secret member (a numeric PIN or password) is replaced by the
			// replacement string; the member's type changes, but the value does not leak.
			end := i + 1
			for end < len(data) && strings.IndexByte("0123456789+-.eE", data[end]) >= 0 {
				end++
			}
			if kind := secretKind(); kind != "" && !e.disabled[kind] && end-i >= minSecretNumberLength {
				out.Write(data[last:i])
				out.Write(encodeJSONString(r.Replace(Finding{Kind: kind, Value: string(data[i:end])})))
				last = end
			}
			i = end
		case '"':
			end := jsonStringEnd(data, i)
			literal := data[i:end]
			decoded, err := decodeJSONString(literal)
			if err != nil {
				return nil, errBadString
			}
			// A token may start at the end of this string and go on in the adjacent one: its
			// rest there is cut off when that string is reached.
			var c cuts
			if heads != nil {
				c.head = heads[i]
			}
			// A value that already continues a token from the value before it is not joined to
			// its name as well, so that each string continues at most one token.
			isName := len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey
			// The checks that rule out most boundaries come first and cost no call.
			if len(decoded) > c.head && splitClass[decoded[len(decoded)-1]]&classSplit != 0 {
				if next, name := adjacentString(data, end, stack); next >= 0 && (!isName || heads == nil || heads[next] == 0) {
					if cut, ok := e.splitAfter(decoded, c.head, data, next, name, stack[len(stack)-1]); ok {
						c.tail = &cut
						if heads == nil {
							heads = map[int]int{}
						}
						heads[next] = max(heads[next], cut.head)
					}
				}
			}
			if isName {
				top := &stack[len(stack)-1]
				// The name as written marks the value; a name that holds a secret itself
				// ({"<token>": "repo"}) is replaced as a string value would be, and a name
				// under a secret member that looks like a value rather than an identifier
				// ({"password": {"hunter2": true}}) is replaced as a whole (see nameShapeOf).
				top.key = decoded
				whole := false
				if top.inherited != "" && !e.disabled[top.inherited] {
					shape, ok := secretNames[decoded]
					if !ok {
						shape = nameShapeOf(decoded)
						secretNames[decoded] = shape
					}
					whole = shape == shapeValue || (shape == shapeWord && onlyFlag(data, end))
				}
				// Most documents repeat a few clean names many times; they are scanned once.
				if _, clean := cleanNames[decoded]; clean && !whole && c.none() {
					i = end
					continue
				}
				var redacted string
				switch {
				case whole:
					redacted = e.redactCut(top.inherited, decoded, c, r)
				case !c.none():
					redacted = e.redactCut("", decoded, c, r)
				default:
					redacted = e.redactJSONValue("", decoded, r, depth)
				}
				if redacted == decoded {
					if !whole && c.none() {
						cleanNames[decoded] = struct{}{}
					}
				} else {
					out.Write(data[last:i])
					if top.taken == nil {
						// Past the budget, names are kept apart from the replacements only.
						names, ok := objectNames(data, top.start, &scanBudget)
						if !ok {
							namesBudgetFallbacks.Add(1)
							names = map[string]bool{}
						}
						top.taken, top.next = names, map[string]int{}
					}
					out.Write(encodeJSONString(uniqueName(top.taken, top.next, redacted)))
					last = end
				}
			} else {
				var redacted string
				if c.none() {
					redacted = e.redactJSONValue(secretKind(), decoded, r, depth)
				} else {
					redacted = e.redactCut(secretKind(), decoded, c, r)
				}
				if redacted != decoded {
					out.Write(data[last:i])
					out.Write(encodeJSONString(redacted))
					last = end
				}
			}
			i = end
		default:
			i++
		}
	}
	if last == 0 {
		return data, nil
	}
	out.Write(data[last:])
	return out.Bytes(), nil
}

// uniqueName returns name, or name#2, name#3 and so on, whichever is not taken yet, and takes
// it, so that no member of an object is lost to a duplicate name. next remembers where the
// search for name stopped.
func uniqueName(taken map[string]bool, next map[string]int, name string) string {
	candidate := name
	n := max(next[name], 2)
	for taken[candidate] {
		candidate = name + "#" + strconv.Itoa(n)
		n++
	}
	next[name] = n
	taken[candidate] = true
	return candidate
}

// objectNames returns the decoded member names of the object whose opening brace is at
// data[start], spending the bytes it reads from budget; ok is false when budget runs out.
// data is valid JSON.
func objectNames(data []byte, start int, budget *int) (names map[string]bool, ok bool) {
	if *budget < 0 {
		return nil, false
	}
	names = map[string]bool{}
	depth, expectKey := 0, false
	for i := start; i < len(data); {
		if *budget--; *budget < 0 {
			return nil, false
		}
		switch data[i] {
		case '{':
			depth++
			expectKey = depth == 1
			i++
		case '[':
			depth++
			i++
		case '}', ']':
			depth--
			if depth == 0 {
				return names, true
			}
			i++
		case ',':
			expectKey = depth == 1
			i++
		case '"':
			end := jsonStringEnd(data, i)
			if expectKey {
				if name, err := decodeJSONString(data[i:end]); err == nil {
					names[name] = true
				}
				expectKey = false
			}
			*budget -= end - i - 1
			i = end
		default:
			i++
		}
	}
	return names, true
}

// jsonStringEnd returns the index just past the closing quote of the string literal starting at
// data[start]. data is valid JSON.
func jsonStringEnd(data []byte, start int) int {
	for i := start + 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(data)
}

func decodeJSONString(literal []byte) (string, error) {
	if !bytes.ContainsRune(literal, '\\') {
		return string(literal[1 : len(literal)-1]), nil
	}
	var s string
	err := json.Unmarshal(literal, &s)
	return s, err
}

func encodeJSONString(s string) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(s); err != nil {
		panic(err) // a string always encodes
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

// adjacentString returns the offset of the string literal adjacent to the one that ends at
// data[end], or -1: for a member name, its value; for a member value, the value of the next
// member; for an array element, the next element. stack is that of rewriteJSON.
func adjacentString(data []byte, end int, stack []frame) (next, name int) {
	if len(stack) == 0 {
		return -1, -1
	}
	top := stack[len(stack)-1]
	i := skipJSONSpace(data, end)
	if top.object && top.expectKey {
		return stringAfter(data, i, ':'), -1
	}
	i = stringAfter(data, i, ',')
	if i < 0 || !top.object {
		return i, -1
	}
	return stringAfter(data, skipJSONSpace(data, jsonStringEnd(data, i)), ':'), i
}

// secretWhole reports whether a value of secret kind kind is replaced whole.
func secretWhole(e *Engine, kind, value string) bool {
	return kind != "" && !e.disabled[kind] && !isPlaceholderValue(value)
}

// memberKind is the secret kind of a value stored under the member name key in an object or
// array whose enclosing secret kind is inherited, or "".
func memberKind(key, inherited string) string {
	if kind, ok := secretKeyKind(key); ok {
		return kind
	}
	if inherited != "" && !slices.Contains(nestedSafeKeys, normalizeKey(key)) {
		return inherited
	}
	return ""
}

// adjacentKind returns the secret kind of the adjacent string at data[next] (see
// adjacentString): a is the decoded string before it, name the offset of the member name between
// them or -1, and top the frame both are in.
func adjacentKind(a string, data []byte, name int, top frame) string {
	switch {
	case top.object && top.expectKey:
		return memberKind(a, top.inherited)
	case name >= 0:
		key, err := decodeJSONString(data[name:jsonStringEnd(data, name)])
		if err != nil {
			return ""
		}
		return memberKind(key, top.inherited)
	default:
		return memberKind(top.key, top.inherited)
	}
}

// stringAfter returns the offset of the string literal that follows sep at data[i] and space,
// or -1.
func stringAfter(data []byte, i int, sep byte) int {
	if i >= len(data) || data[i] != sep {
		return -1
	}
	i = skipJSONSpace(data, i+1)
	if i >= len(data) || data[i] != '"' {
		return -1
	}
	return i
}

func skipJSONSpace(data []byte, i int) int {
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	return i
}

// splitLeftOnly is the start of the window of a split token in a (see splitLeft).
func splitLeftOnly(a string, from int) int {
	left, _ := splitLeft(a, from)
	return left
}

// splitAfter looks for a token that starts in the decoded string a, at or after from, and goes
// on in the string literal at data[next] (see splitToken). The literal is decoded only when the
// window passes splitHintOf and maySplit on its raw bytes; maySplit is checked again on the
// decoded run, which differs when an escape is in it. name and top are as adjacentKind takes
// them. When the second string is a secret member's value, replaced whole anyway, the first part
// is cut alone, with no continuation.
func (e *Engine) splitAfter(a string, from int, data []byte, next, name int, top frame) (splitCut, bool) {
	if len(a) <= from || !isSplitByte(a[len(a)-1]) || next+1 >= len(data) || (!isSplitByte(data[next+1]) && data[next+1] != '\\') {
		return splitCut{}, false
	}
	if data[next+1] != '\\' {
		// Most boundaries are ruled out by one look at the run that ends a.
		left, hint := splitHintOf(a, from, data[next+1])
		if hint == 0 {
			return splitCut{}, false
		}
		run := next + 1
		for run < len(data) && run-next <= splitWindow && splitClass[data[run]]&classSplit != 0 {
			run++
		}
		if data[run] != '\\' {
			if hint == hintDigit && len(a)-left+run-next-1 < minTelegramToken {
				return splitCut{}, false
			}
			if hint&hintLong != 0 {
				left = splitLeftOnly(a, from)
			}
			if !maySplit(a[left:], data[next+1:run]) {
				return splitCut{}, false
			}
		}
	}
	b, err := decodeJSONString(data[next:jsonStringEnd(data, next)])
	if err != nil {
		return splitCut{}, false
	}
	head := 0
	for head < len(b) && head < splitWindow && isSplitByte(b[head]) {
		head++
	}
	if !maySplit(a[splitLeftOnly(a, from):], b[:head]) {
		return splitCut{}, false
	}
	aWhole := (!top.object || !top.expectKey) && secretWhole(e, memberKind(top.key, top.inherited), a)
	cut, ok := e.splitToken(a, from, b, aWhole)
	// A second string that is replaced whole anyway, as a secret member's value, keeps its own
	// finding: the first part is replaced on its own, with no continuation.
	if ok && secretWhole(e, adjacentKind(a, data, name, top), b) {
		cut.head, cut.value = 0, a[cut.tail:]
	}
	return cut, ok
}

// nameShape is what a member name under a secret member looks like, as nameShapeOf finds it.
type nameShape uint8

const (
	// shapeKept is a plain identifier, a name in nestedSafeKeys or a placeholder: never replaced.
	shapeKept nameShape = iota + 1
	// shapeWord is a name of letters, not random, that is no plain identifier: replaced when its
	// value is only a flag.
	shapeWord
	// shapeValue holds a digit or a symbol or is random: always replaced.
	shapeValue
)

// nameShapeOf classifies a member name under a secret member: it is replaced as a whole when it
// is not in nestedSafeKeys, not a plain identifier (lower-case, snake, kebab, camel or upper
// snake case), and either holds a digit or a symbol or has high entropy, or its value is only a
// flag (see onlyFlag).
func nameShapeOf(name string) nameShape {
	switch {
	case plainIdentifier.MatchString(name) || isPlaceholderValue(name) || slices.Contains(nestedSafeKeys, normalizeKey(name)):
		return shapeKept
	case identifierShaped(name):
		return shapeWord
	default:
		return shapeValue
	}
}

// plainIdentifier matches the names of members as code writes them: "expires_in", "token-type",
// "tokenType", "TokenType", "userID", "TOKEN_TYPE". Digits count only in the well-known words of
// digitWords, alone or as a part of such a name ("oauth2", "auth_provider_x509_cert_url",
// "sha256Hash", "oauth2Token"); any other word with digits ("hunter2", "MyPassword1",
// "Summer2024Sale") is no plain identifier.
var plainIdentifier = regexp.MustCompile(`^(?:` +
	`_?(?:[a-z]+|` + digitWords + `)(?:[_-](?:[a-z]+|` + digitWords + `))*` +
	`|_?(?:[A-Z]+|` + upperDigitWords + `)(?:_(?:[A-Z]+|` + upperDigitWords + `))*` +
	`|(?:[A-Za-z][a-z]+|` + digitWords + `)(?:[A-Z][a-z]+|` + titleDigitWords + `)*[A-Z]*` +
	`)$`)

// digitWords are the well-known words with digits that identifiers hold, in lower case;
// upperDigitWords and titleDigitWords are the same words in upper and title case.
const (
	digitWords      = `(?:oauth[12]|sha(?:1|224|256|384|512)|md5|base(?:32|64)|x509|utf(?:8|16)|ipv[46]|http[23]|v[0-9])`
	upperDigitWords = `(?:OAUTH[12]|SHA(?:1|224|256|384|512)|MD5|BASE(?:32|64)|X509|UTF(?:8|16)|IPV[46]|HTTP[23]|V[0-9])`
	titleDigitWords = `(?:Oauth[12]|OAuth[12]|Sha(?:1|224|256|384|512)|Md5|Base(?:32|64)|X509|Utf(?:8|16)|Ipv[46]|IPv[46]|Http[23]|V[0-9])`
)

// The length and Shannon entropy, in bits per byte, from which a name of letters only counts as
// random rather than as an identifier.
const (
	minRandomNameLength  = 12
	minRandomNameEntropy = 3.5
)

// identifierShaped reports whether a name that is not a plain identifier still looks like one:
// letters only, and not random.
func identifierShaped(name string) bool {
	for _, r := range name {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return len(name) < minRandomNameLength || shannonEntropy(name) < minRandomNameEntropy
}

// onlyFlag reports whether the value after the member name that ends at data[end] is only a
// flag: true, false, null, a number, {}, [] or "".
func onlyFlag(data []byte, end int) bool {
	i := skipJSONSpace(data, end)
	if i >= len(data) || data[i] != ':' {
		return false
	}
	i = skipJSONSpace(data, i+1)
	if i >= len(data) {
		return false
	}
	switch c := data[i]; {
	case c == 't' || c == 'f' || c == 'n' || c == '-' || (c >= '0' && c <= '9'):
		return true
	case c == '"':
		return i+1 < len(data) && data[i+1] == '"'
	case c == '{' || c == '[':
		j := skipJSONSpace(data, i+1)
		return j < len(data) && (data[j] == '}' || data[j] == ']')
	}
	return false
}
