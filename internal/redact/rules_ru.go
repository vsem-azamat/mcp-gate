package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Russian credential labels, for chats in Russian (Options.Russian).

// russianLabelSeparators are the characters that make "label X" an explicit "label: X".
const russianLabelSeparators = ":=：—–-"

// russianTechValue matches values that follow "ключ"/"токен" in ordinary talk about crypto and
// keys ("токен ERC-20", "ключ: ED25519", "ключ - 12:30", "секрет: 50%") rather than a
// credential.
var russianTechValue = regexp.MustCompile(`^(?:[A-Z0-9][A-Z0-9-]{1,11}|\d{1,2}:\d{2}|\d{1,5}%?|ssh-[a-z0-9-]+)$`)

// russianLabelValueGroup is the capture group of an unquoted value in the label rules.
const russianLabelValueGroup = 8

// The parts of the label rules: the label (group 1) with its qualifier (group 2), the explicit
// separator, and the value (groups 4 to 8, the last unquoted). Group 3 is the separator with its
// space, which each rule writes around russianLabelSeparator.
const (
	russianLabelPattern = `(?i)(?:^|[^\p{L}\p{N}_])(пароль|пароля|паролем|пароли|токен|токена|ключ|ключа|апи[\s\-]*ключ|секрет|код\s+доступа)` +
		`((?:[ \t]+(?:от|к|для|на|доступа)(?:[ \t]+[^\s:=：—–\-]{1,30}){0,2})?)` + zeroWidth
	russianLabelSeparator = `(?:[:=：]|--?|[—–])`
	russianLabelValue     = "(?:\"([^\"\\r\\n]+)\"|«([^»\\r\\n]+)»|'([^'\\r\\n]+)'|`([^`\\r\\n]+)`|([^\\s\"«»'`]+))"
)

// russianLabelPrefilter holds the substrings one of which a Russian label contains.
var russianLabelPrefilter = []string{"пароль", "парол", "токен", "ключ", "секрет", "код"}

var russianRules = []*rule{
	{
		// "логин/пароль: admin / Qwerty123" covers the rest of the line.
		kind:      kindPassword,
		priority:  priorityRussianPair,
		set:       setRussian,
		re:        regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])(логин\s*(?:/|и)\s*пароль)` + zeroWidth + `\s*(?:[:=：]|[—–-])\s*([^\r\n]+)`),
		groups:    []int{2},
		prefilter: []string{"пароль"},
		accept:    russianPairAccept,
	},
	{
		// "пароль: X", "пароль от почты: X", "токен — X", "ключ = X", "пароль Qwerty-123".
		kind:      kindPassword,
		priority:  priorityRussianLabel,
		set:       setRussian,
		re:        regexp.MustCompile(russianLabelPattern + `([ \t]*` + russianLabelSeparator + `[ \t]*|[ \t]+)` + russianLabelValue),
		groups:    []int{4, 5, 6, 7, 8},
		prefilter: russianLabelPrefilter,
		accept:    russianLabelAccept,
	},
	{
		// "Пароль:" at the end of a line and the value at the start of the next one. A separate
		// rule, matched on each such line and the line after it, so that a next line it rejects
		// ("токен: X", "username: alice") is still matched by the rule above.
		kind:      kindPassword,
		priority:  priorityRussianLabelNextLine,
		set:       setRussian,
		re:        regexp.MustCompile(russianLabelPattern + `([ \t]*` + russianLabelSeparator + `[ \t]*\r?\n[ \t]*)` + russianLabelValue),
		groups:    []int{4, 5, 6, 7, 8},
		prefilter: russianLabelPrefilter,
		regions:   russianKeyLineRegions,
		accept:    russianNextLineAccept,
	},
}

func russianPairAccept(text string, _ []int, start, end int) (int, int, string, bool) {
	end = start + len(strings.TrimRight(text[start:end], " \t"))
	value := text[start:end]
	if isPlaceholderValue(value) || onlyCyrillicLetters(value) {
		return 0, 0, "", false
	}
	return start, end, kindPassword, true
}

// russianLabelAccept validates a value after a Russian label. With an explicit separator,
// anything but a placeholder or plain Cyrillic words counts ("токен: истёк" is prose). Without
// one ("пароль Qwerty123"), the value must look like a password: no Cyrillic, at least 6
// characters, mixed case or letters with digits and symbols.
func russianLabelAccept(text string, match []int, start, end int) (int, int, string, bool) {
	label := strings.ToLower(text[match[2]:match[3]])
	qualified := match[5] > match[4]
	separator := text[match[6]:match[7]]
	explicit := strings.ContainsAny(separator, russianLabelSeparators)
	if qualified && !explicit {
		return 0, 0, "", false // "пароль от почты сменили"
	}
	if unquoted := match[2*russianLabelValueGroup] >= 0 && match[2*russianLabelValueGroup] == start; unquoted {
		end = trimTrailingPunctuation(text, start, end)
	}
	value := text[start:end]
	if isPlaceholderValue(value) || onlyCyrillicLetters(value) {
		return 0, 0, "", false
	}
	isPassword := strings.HasPrefix(label, "парол") || strings.HasPrefix(label, "код")
	// A token or key is never a plain word ("токен — Telegram выдаёт").
	if !isPassword && (russianTechValue.MatchString(value) || strings.IndexFunc(value, func(r rune) bool { return !unicode.IsLetter(r) }) < 0) {
		return 0, 0, "", false
	}
	if !explicit && !passwordShaped(value) {
		return 0, 0, "", false
	}
	kind := kindSecret
	if isPassword {
		kind = kindPassword
	}
	return start, end, kind, true
}

// russianNextLineAccept accepts a value at the start of the line after a Russian label as
// russianLabelAccept does, unless that line is a key-value pair of its own ("username: alice",
// "токен: X"): an unquoted value that ends with a separator, or is followed by one, with more
// text after it on its line.
func russianNextLineAccept(text string, match []int, start, end int) (int, int, string, bool) {
	if g := russianLabelValueGroup; match[2*g] >= 0 && opensPair(text, match[2*g], match[2*g+1]) {
		return 0, 0, "", false
	}
	return russianLabelAccept(text, match, start, end)
}

// opensPair reports whether the unquoted run text[start:end] is the key of a pair on its line:
// it holds no escaped line break, ends with, or is followed by space and, one of ":", "=" or
// "：", and more than space follows on the line.
func opensPair(text string, start, end int) bool {
	lineEnd := len(text)
	if i := strings.IndexByte(text[end:], '\n'); i >= 0 {
		lineEnd = end + i
	}
	rest := trimLeftSet(text[end:lineEnd], " \t")
	run := text[start:end]
	if strings.IndexByte(run, maskedBreak) >= 0 {
		return false // the run goes on over an escaped line break, after which a pair may start
	}
	switch {
	case strings.HasSuffix(run, ":") || strings.HasSuffix(run, "=") || strings.HasSuffix(run, "："):
	case strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "="):
		rest = rest[1:]
	case strings.HasPrefix(rest, "："):
		rest = rest[len("："):]
	default:
		return false
	}
	return strings.TrimSpace(rest) != ""
}

// russianKeyLineRegions returns, for the Russian next-line rule, each line that ends, before
// spaces and a carriage return, with a label separator and holds a Russian label in its last
// maxKeyLineWindow bytes, together with the line after it.
func russianKeyLineRegions(text string) []region {
	var regions []region
	for lineStart := 0; lineStart < len(text); {
		i := strings.IndexByte(text[lineStart:], '\n')
		if i < 0 {
			break
		}
		start, lineEnd := lineStart, lineStart+i
		lineStart = lineEnd + 1
		key := trimRightSet(text[start:lineEnd], " \t\r")
		if !hasRussianSeparatorSuffix(key) {
			continue
		}
		windowStart := max(start, start+len(key)-maxKeyLineWindow)
		for windowStart < len(text) && !utf8.RuneStart(text[windowStart]) {
			windowStart++
		}
		if !containsAny(strings.ToLower(text[windowStart:start+len(key)]), russianLabelPrefilter) {
			continue
		}
		valueEnd := len(text)
		if j := strings.IndexByte(text[lineStart:], '\n'); j >= 0 {
			valueEnd = lineStart + j
		}
		regions = append(regions, region{start: windowStart, end: valueEnd})
	}
	return regions
}

// hasRussianSeparatorSuffix reports whether line ends with a separator of the Russian label
// rules.
func hasRussianSeparatorSuffix(line string) bool {
	r, _ := utf8.DecodeLastRuneInString(line)
	return r != utf8.RuneError && strings.ContainsRune(russianLabelSeparators, r)
}

func onlyCyrillicLetters(value string) bool {
	for _, r := range value {
		if !unicode.Is(unicode.Cyrillic, r) && r != '-' && r != ' ' && r != ',' && r != '.' {
			return false
		}
	}
	return true
}

// minPasswordShapedLength is the length a value after a label without a separator needs.
const minPasswordShapedLength = 6

func passwordShaped(value string) bool {
	if len([]rune(value)) < minPasswordShapedLength {
		return false
	}
	var upper, lower, digit, symbol bool
	for _, r := range value {
		switch {
		case unicode.Is(unicode.Cyrillic, r):
			return false
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	return (upper && lower && (digit || symbol)) || (lower && digit && symbol)
}
