package redact

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// The next-line key-value rule: a key at the end of a line ("password:") and its value alone on
// the line after it.

// keyLineEndSpace is what may follow the separator of a key line before the line break: the
// separator space, an escaped tab (maskedTab) and zero-width spaces.
const keyLineEndSpace = separatorSpace + "\x01" + zeroWidthChars

// maxKeyLineWindow bounds how much of a key line, back from its separator, the rule matches: a
// key, its quote and the space before the separator fit in it many times over.
const maxKeyLineWindow = 512

// maxNextLineValue is the longest next line, without its surrounding space, that is taken as a
// value.
const maxNextLineValue = 8192

// region is a part of a text, text[start:end], that a rule matches.
type region struct{ start, end int }

// keyLineRegions returns, for the next-line key-value rule, each line that ends, before
// keyLineEndSpace and a carriage return, with one of keyValueSeparators and holds a key word,
// together with the line after it when that line can be a value alone (see mayBeValueLine).
// Matching only there keeps the rule's cost to the lines it can match, and gives every key line
// its own match even when the line before it is a key line too. A region holds at most one
// match, whose value is on its last line, so the matches stay in order.
//
// A region starts at most maxKeyLineWindow bytes before the separator, and only after a byte
// that cannot be part of a key, so that ^ there stands for the key's left boundary as it does in
// the whole text.
func keyLineRegions(text string) []region {
	if strings.IndexByte(text, ':') < 0 && strings.IndexByte(text, '=') < 0 && !strings.Contains(text, "：") {
		return nil
	}
	var regions []region
	for lineStart := 0; lineStart < len(text); {
		i := strings.IndexByte(text[lineStart:], '\n')
		if i < 0 {
			break
		}
		start, lineEnd := lineStart, lineStart+i
		lineStart = lineEnd + 1
		keyEnd := start + len(trimRightSet(text[start:lineEnd], keyLineEndSpace+"\r"))
		if !hasSeparatorSuffix(text[start:keyEnd]) || opensBlock(text[start:keyEnd]) {
			continue
		}
		windowStart := keyWindowStart(text, start, keyEnd)
		if !containsAny(strings.ToLower(text[windowStart:keyEnd]), keyValuePrefilter) {
			continue
		}
		valueEnd := len(text)
		if j := strings.IndexByte(text[lineStart:], '\n'); j >= 0 {
			valueEnd = lineStart + j
		}
		if !mayBeValueLine(text[lineStart:valueEnd]) {
			continue
		}
		regions = append(regions, region{start: windowStart, end: valueEnd})
	}
	return regions
}

// keyWindowStart returns where the region of a key line text[lineStart:keyEnd] starts: at most
// maxKeyLineWindow bytes before keyEnd, after a byte that is not a key character.
func keyWindowStart(text string, lineStart, keyEnd int) int {
	cut := keyEnd - maxKeyLineWindow
	if cut <= lineStart {
		return lineStart
	}
	for cut < keyEnd && isKeyByte(text[cut-1]) {
		cut++
	}
	return cut
}

// isKeyByte reports whether c can be part of a key of keyValueKey.
func isKeyByte(c byte) bool {
	return isTokenByte(c) || c == '.'
}

// hasSeparatorSuffix reports whether line ends with one of keyValueSeparators.
func hasSeparatorSuffix(line string) bool {
	for _, sep := range keyValueSeparators {
		if strings.HasSuffix(line, sep) {
			return true
		}
	}
	return false
}

// mayBeValueLine is a cheap check that a line can hold a value alone as the rule's expression
// requires; it may pass lines the expression then rejects, never the other way round. A quoted
// value ends with its quote (and maybe a comma or semicolon); an unquoted one has no space or tab
// inside and does not end with a colon.
func mayBeValueLine(line string) bool {
	v := trimRightSet(trimLeftSet(line, separatorSpace), separatorSpace+"\r")
	if v == "" || len(v) > maxNextLineValue {
		return false
	}
	if q := v[0]; q == '"' || q == '\'' {
		if last := v[len(v)-1]; last == ',' || last == ';' {
			v = v[:len(v)-1]
		}
		return len(v) >= 3 && v[len(v)-1] == q
	}
	return !strings.ContainsAny(v, " \t") && v[len(v)-1] != ':'
}

// trimLeftSet and trimRightSet drop the characters of set from one end of s, checking an ASCII
// byte without decoding it.
func trimLeftSet(s, set string) string {
	for s != "" {
		if c := s[0]; c < utf8.RuneSelf {
			if strings.IndexByte(set, c) < 0 {
				break
			}
			s = s[1:]
			continue
		}
		r, size := utf8.DecodeRuneInString(s)
		if !strings.ContainsRune(set, r) {
			break
		}
		s = s[size:]
	}
	return s
}

func trimRightSet(s, set string) string {
	for s != "" {
		if c := s[len(s)-1]; c < utf8.RuneSelf {
			if strings.IndexByte(set, c) < 0 {
				break
			}
			s = s[:len(s)-1]
			continue
		}
		r, size := utf8.DecodeLastRuneInString(s)
		if !strings.ContainsRune(set, r) {
			break
		}
		s = s[:len(s)-size]
	}
	return s
}

// nextLineUnquotedGroup is the capture group of an unquoted value in the next-line rule.
const nextLineUnquotedGroup = 4

// controlKeywords are statements that make up the body of a block in code ("if token:\n
// return"), not values. "else" stays for shell and Ruby, where it ends no line with a colon.
var controlKeywords = map[string]bool{
	"return": true, "pass": true, "continue": true, "break": true, "yield": true, "raise": true,
	"else": true, "elif": true, "then": true, "do": true, "done": true, "fi": true, "end": true,
	"endif": true, "esac": true, "begin": true, "ensure": true,
}

// blockHeaders are the first words of a line of code that opens a block ("if not token:",
// "case 'password':"); its next line is the block's body, not a value.
var blockHeaders = map[string]bool{
	"if": true, "elif": true, "while": true, "for": true, "with": true, "case": true,
	"match": true, "except": true, "def": true, "class": true, "switch": true,
}

// keyName matches a whole name of the shape keyValueKey takes.
var keyName = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// upperName and lowerName match the names of configuration assignments: UPPER_SNAKE of at least
// two characters, or lower-case.
var (
	upperName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]+$`)
	lowerName = regexp.MustCompile(`^[a-z_][a-z0-9_.\-]*$`)
)

// proseKeyValueAccept is the accept function of the key-value rules: proseKeyKind classifies the
// key, and the last of the three value groups is unquoted.
var proseKeyValueAccept = keyValueAccept(proseKeyKind, 3)

// nextLineValueAccept accepts a value alone on the line after its key as proseKeyValueAccept
// does, unless the key line opens a block of code, or an unquoted value is the structure of the
// text rather than a value (see isNextLineStructure).
func nextLineValueAccept(text string, match []int, start, end int) (int, int, string, bool) {
	if opensBlock(text[strings.LastIndexByte(text[:match[2]], '\n')+1 : match[3]]) {
		return 0, 0, "", false
	}
	if g := nextLineUnquotedGroup; match[2*g] >= 0 && isNextLineStructure(text[match[2*g]:match[2*g+1]]) {
		return 0, 0, "", false
	}
	return proseKeyValueAccept(text, match, start, end)
}

// opensBlock reports whether a key line, up to its key or its separator, is a line of code that
// opens a block: after its indentation, one of blockHeaders, then only an optional "not" and
// the key ("if token", "if not token", "case 'token'", "if(token)"), or any number of words
// when one before the key is an operator word or holds an operator character ("while retries
// and token", "if len(token)"). A header word in prose ("for the staging db password") opens
// no block. keyLineRegions skips such key lines before matching, passing the line up to its
// separator, and nextLineValueAccept rejects them, passing the line up to the end of the key;
// opensBlock drops a trailing separator, quote and space, so that both see the same words.
func opensBlock(line string) bool {
	line = strings.TrimLeft(line, " \t")
	n := 0
	for n < len(line) && (line[n] >= 'a' && line[n] <= 'z') {
		n++
	}
	if n == len(line) || !blockHeaders[line[:n]] || isKeyByte(line[n]) {
		return false
	}
	words := strings.Fields(trimRightSet(line, keyLineEndSpace+`:=>："'`))
	if len(words) <= 2 || (len(words) == 3 && words[1] == "not") {
		return true
	}
	for _, word := range words[1 : len(words)-1] {
		if operatorWords[word] || strings.ContainsAny(word, "()[]=!<>&|") {
			return true
		}
	}
	return false
}

// operatorWords are the words of a condition in code ("while retries and token:").
var operatorWords = map[string]bool{"and": true, "or": true, "not": true, "in": true, "is": true}

// isNextLineStructure reports whether an unquoted next line is the structure of the text rather
// than a value: a Markdown code fence, a URL ("Reset your password:\nhttps://…"), a control
// statement of code ("return;"), a secret key of its own whose value is on the line after it
// ("API_KEY="), or a configuration assignment ("DEBUG=True", "DB_HOST=").
func isNextLineStructure(value string) bool {
	if strings.HasPrefix(value, "```") || strings.HasPrefix(value, "~~~") || strings.Contains(value, "://") ||
		controlKeywords[strings.TrimRight(value, ";,")] {
		return true
	}
	for _, sep := range keyValueSeparators {
		if name, ok := strings.CutSuffix(value, sep); ok && keyName.MatchString(name) {
			if _, secret := proseKeyKind(name); secret {
				return true
			}
		}
	}
	return isConfigAssignment(value)
}

// isConfigAssignment reports whether value is a configuration assignment NAME=rest: an UPPER_SNAKE
// name ("DEBUG=True", "DB_HOST=", "TZ=Europe/Prague") or a lower-case one with "_"
// ("db_host=") with any rest; a lower-case name with nothing after "=" ("debug="); or a
// lower-case name with a rest that does not mix upper and lower case ("log=info"). Generated
// passwords that hold "=" ("Kj8=xP2qLm", "Hunter=22x") and base64 padding ("c2VjcmV0=",
// "abc==") are values.
func isConfigAssignment(value string) bool {
	name, rest, ok := strings.Cut(value, "=")
	if !ok || strings.HasPrefix(rest, "=") {
		return false
	}
	if upperName.MatchString(name) {
		return true
	}
	if !lowerName.MatchString(name) {
		return false
	}
	if rest == "" || strings.Contains(name, "_") {
		return true
	}
	var upper, lower bool
	for i := range len(rest) {
		c := rest[i]
		upper = upper || c >= 'A' && c <= 'Z'
		lower = lower || c >= 'a' && c <= 'z'
	}
	return !upper || !lower
}
