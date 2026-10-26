package redact

import (
	"cmp"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// rule finds one kind of secret in text.
type rule struct {
	kind string
	// priority orders the rules: a lower number runs first, and when findings overlap, the
	// merged finding takes the kind of the rule with the lowest number. Every rule has its own
	// number.
	priority int
	// set is the option that enables the rule.
	set ruleSet
	re  *regexp.Regexp
	// groups lists the capture groups that may hold the secret; the first non-empty one is
	// used. Empty means the whole match.
	groups []int
	// prefilter holds lower-case substrings at least one of which must occur in the text for
	// the rule to run at all. Empty means always run.
	prefilter []string
	// precheck, when set, is a cheap scan that must pass for the rule to run.
	precheck func(text string) bool
	// regions, when set, returns the parts of the text the expression runs over, each holding at
	// most one match, so only the first is taken. They may overlap, but what is accepted in one
	// must end before what is accepted in the next starts. None means the rule does not run.
	regions func(text string) []region
	// accept validates a candidate and may narrow it or change its kind ("" keeps the rule's
	// kind). It receives the whole text, the submatch indexes and the selected span.
	accept acceptFunc
	// jsonEscaped marks a value written inside a JSON string literal; a Replacer gets it
	// decoded.
	jsonEscaped bool
	// split marks a vendor-format rule, which also runs over the boundary of two adjacent JSON
	// strings (see splitToken). Its matches hold only splitBytes, and it has a prefilter or a
	// precheck.
	split bool
}

type acceptFunc func(text string, match []int, start, end int) (newStart, newEnd int, kind string, ok bool)

// ruleSet is the option a rule belongs to.
type ruleSet int

const (
	setCore        ruleSet = iota // always on
	setHighEntropy                // Options.HighEntropy
	setRussian                    // Options.Russian
)

// Kinds that accept functions emit.
const (
	kindPassword = "password"
	kindSecret   = "secret"
)

// allRules returns every rule, sorted by priority. The slice is shared and must not be changed.
func allRules() []*rule { return sortedRules }

var sortedRules = sortRules(slices.Concat(coreRules, highEntropyRules, russianRules))

// sortRules orders rules by priority and panics on a duplicate, so that the order never
// depends on how the rule lists were concatenated.
func sortRules(rules []*rule) []*rule {
	slices.SortFunc(rules, func(a, b *rule) int { return cmp.Compare(a.priority, b.priority) })
	for i := 1; i < len(rules); i++ {
		if rules[i].priority == rules[i-1].priority {
			panic(fmt.Sprintf("redact: rules %s and %s share priority %d", rules[i-1].kind, rules[i].kind, rules[i].priority))
		}
	}
	return rules
}

// Rule priorities. Specific formats come before generic key-value rules, and the entropy
// heuristic comes late. The Russian "login/password" pair rule runs before every other rule, so
// that no other finding on its line can split it and leave the password visible; the Russian
// label rule runs last.
const (
	priorityRussianPair          = 10
	priorityPrivateKey           = 100
	priorityAWSAccessKey         = 110
	priorityAWSSecretKey         = 120
	priorityGitHubToken          = 130
	priorityGitLabToken          = 140
	priorityAnthropicAPIKey      = 150
	priorityOpenAIAPIKey         = 160
	priorityGoogleAPIKey         = 170
	priorityGoogleOAuthToken     = 180
	prioritySlackToken           = 190
	prioritySlackWebhook         = 200
	priorityTelegramBotToken     = 210
	priorityStripeKey            = 220
	priorityJWT                  = 230
	priorityAuthHeader           = 240
	priorityURLPassword          = 250
	priorityEnvAssignment        = 300
	priorityKeyValue             = 310
	priorityKeyValueNextLine     = 315
	priorityCLIFlag              = 320
	priorityJSONFragment         = 330
	priorityHighEntropy          = 900
	priorityRussianLabel         = 910
	priorityRussianLabelNextLine = 920
)

// zeroWidthChars are the invisible characters sometimes used to break up a label
// ("pass\u200bword:"), and zeroWidth matches a run of them.
const (
	zeroWidthChars = "\u200b\u200c\u200d\u2060\ufeff"
	zeroWidth      = `[` + zeroWidthChars + `]*`
)

// separatorSpace is the space the key-value rules allow around a separator.
const separatorSpace = " \t\u00a0"

// keyValueSeparators are the separators of a key-value pair, and keyValueSeparator matches one
// of them; TestKeyValueSeparators keeps the two in step. The expression is written with a
// character class, which the regexp engine runs faster than an alternation of single letters.
var keyValueSeparators = []string{":=", "=>", ":", "=", "："}

const keyValueSeparator = `(?::=|=>|[:=]|：)`

// keyValueKey matches the key of a "key: value" pair (group 1) and its separator. The key may
// carry any prefix (MYSQL_ROOT_PASSWORD, userPassword); proseKeyKind classifies it.
const keyValueKey = `(?:^|[^A-Za-z0-9_.\-])([A-Za-z0-9_.\-]{0,64}?(?:password|passwd|pwd|passphrase|pass|secret|api[_\-. ]?key|apikey|token|private[_\-]?key|secret[_\-]?key))` +
	zeroWidth + `["']?[` + separatorSpace + `]*` + keyValueSeparator

// keyValuePrefilter holds the substrings one of which a key of keyValueKey contains.
var keyValuePrefilter = []string{"pass", "pwd", "secret", "key", "token"}

var coreRules = []*rule{
	{
		kind:      "private_key",
		priority:  priorityPrivateKey,
		re:        regexp.MustCompile(`-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----|[\s\S]*)`),
		prefilter: []string{"private key"},
	},
	{
		kind:      "aws_access_key",
		priority:  priorityAWSAccessKey,
		split:     true,
		re:        regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`),
		groups:    []int{1},
		prefilter: []string{"akia", "asia", "abia", "acca"},
	},
	{
		kind:      "aws_secret_key",
		priority:  priorityAWSSecretKey,
		re:        regexp.MustCompile(`(?i)aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`),
		groups:    []int{1},
		prefilter: []string{"aws"},
	},
	{
		kind:      "github_token",
		priority:  priorityGitHubToken,
		split:     true,
		re:        regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`),
		groups:    []int{1},
		prefilter: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
	},
	{
		kind:      "gitlab_token",
		priority:  priorityGitLabToken,
		split:     true,
		re:        regexp.MustCompile(`\b((?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glsoat|glffct|glwt)-[A-Za-z0-9_.\-]{20,}|GR1348941[A-Za-z0-9_\-]{20,})`),
		groups:    []int{1},
		prefilter: []string{"glpat-", "gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "glsoat-", "glffct-", "glwt-", "gr1348941"},
	},
	{
		kind:      "anthropic_api_key",
		priority:  priorityAnthropicAPIKey,
		split:     true,
		re:        regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9]{2,12}-[A-Za-z0-9_\-]{20,})`),
		groups:    []int{1},
		prefilter: []string{"sk-ant-"},
	},
	{
		kind:      "openai_api_key",
		priority:  priorityOpenAIAPIKey,
		split:     true,
		re:        regexp.MustCompile(`\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,})\b`),
		groups:    []int{1},
		prefilter: []string{"sk-"},
	},
	{
		kind:      "google_api_key",
		priority:  priorityGoogleAPIKey,
		split:     true,
		re:        regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})`),
		groups:    []int{1},
		prefilter: []string{"aiza"},
	},
	{
		kind:      "google_oauth_token",
		priority:  priorityGoogleOAuthToken,
		split:     true,
		re:        regexp.MustCompile(`\b(ya29\.[A-Za-z0-9_\-]{20,}|GOCSPX-[A-Za-z0-9_\-]{20,}|1//0[A-Za-z0-9_\-]{40,})`),
		groups:    []int{1},
		prefilter: []string{"ya29.", "gocspx-", "1//0"},
	},
	{
		kind:      "slack_token",
		priority:  prioritySlackToken,
		split:     true,
		re:        regexp.MustCompile(`\b(xox[abposre]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9\-]{10,})`),
		groups:    []int{1},
		prefilter: []string{"xox", "xapp-"},
	},
	{
		kind:      "slack_webhook",
		priority:  prioritySlackWebhook,
		split:     true,
		re:        regexp.MustCompile(`(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/\-]{20,})`),
		groups:    []int{1},
		prefilter: []string{"hooks.slack.com"},
	},
	{
		kind:     "telegram_bot_token",
		priority: priorityTelegramBotToken,
		split:    true,
		re:       regexp.MustCompile(`\b(?:bot)?(\d{6,16}:[A-Za-z0-9_\-]{35})(?:[^A-Za-z0-9_\-]|$)`),
		groups:   []int{1},
		precheck: hasDigitColonRun,
	},
	{
		kind:      "stripe_key",
		priority:  priorityStripeKey,
		split:     true,
		re:        regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})`),
		groups:    []int{1},
		prefilter: []string{"_live_", "_test_"},
	},
	{
		kind:      "jwt",
		priority:  priorityJWT,
		split:     true,
		re:        regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})`),
		groups:    []int{1},
		prefilter: []string{"eyj"},
	},
	{
		kind:      "auth_header",
		priority:  priorityAuthHeader,
		re:        regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest)\s+([A-Za-z0-9._~+/=\-]{8,})`),
		groups:    []int{1},
		prefilter: []string{"authorization"},
	},
	{
		kind:     "url_password",
		priority: priorityURLPassword,
		re:       regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]{1,30}://[^\s:/?#@"'<>]*:([^\s/?#"'<>]+)@`),
		groups:   []int{1},
		precheck: hasURLUserinfo,
		accept:   rejectPlaceholder,
	},
	{
		// KEY=value lines of .env files and shell exports.
		kind:      "env_secret",
		priority:  priorityEnvAssignment,
		re:        regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]{0,127})[ \t]*=[ \t]*(?:"((?:[^"\\\r\n]|\\.)*)"|'([^'\r\n]*)'|([^\s"'#][^\r\n]*?))[ \t]*(?:[ \t]#[^\r\n]*)?\r?$`),
		groups:    []int{2, 3, 4},
		prefilter: []string{"pass", "secret", "token", "key", "auth", "dsn", "credential", "private"},
		precheck:  func(text string) bool { return strings.Contains(text, "=") },
		accept:    keyValueAccept(envKeyKind, 3),
	},
	{
		// "password: x", "api_key = x", "token=x", "password := x" in prose, YAML, INI, code
		// and query strings.
		kind:      kindSecret,
		priority:  priorityKeyValue,
		re:        regexp.MustCompile(`(?i)` + keyValueKey + `[` + separatorSpace + `]*(?:"([^"\r\n]{1,})"|'([^'\r\n]{1,})'|([^\s"'<>&]{1,}))`),
		groups:    []int{2, 3, 4},
		prefilter: keyValuePrefilter,
		precheck:  func(text string) bool { return strings.ContainsAny(text, ":=：") },
		accept:    proseKeyValueAccept,
	},
	{
		// "password:" at the end of a line and the value alone on the next one ("password:\n
		// hunter22", YAML's "password:\n  hunter22"). A separate rule rather than an optional
		// line break in the rule above, so that a next line it rejects is still scanned by that
		// rule. Each key line is matched on its own region, so a key line after it
		// ("token:\nabc…", "API_KEY=\nabc…") is matched with its own value.
		kind:     kindSecret,
		priority: priorityKeyValueNextLine,
		re: regexp.MustCompile(`(?im)` + keyValueKey + `[` + keyLineEndSpace + `]*\r?\n[` + separatorSpace + `]*` +
			`(?:"([^"\r\n]{1,})"|'([^'\r\n]{1,})'|([^\s"'<>&]*[^\s"'<>&:]))[,;]?[` + separatorSpace + `]*\r?$`),
		groups:  []int{2, 3, 4},
		regions: keyLineRegions,
		accept:  nextLineValueAccept,
	},
	{
		// Command-line flags: --password x, --token=x.
		kind:      kindSecret,
		priority:  priorityCLIFlag,
		re:        regexp.MustCompile(`(?:^|\s)--?((?:db-|mysql-|admin-)?(?:password|passwd|pass|token|api-key|apikey|secret|client-secret))(?:=|[ \t]+)([^\s"'-][^\s"']*)`),
		groups:    []int{2},
		prefilter: []string{"--", "-pass", "-token", "-secret", "-api"},
		accept:    keyValueAccept(proseKeyKind, 0),
	},
	{
		// "key": "value" fragments in text that is not itself valid JSON. Also matches escaped
		// JSON inside a string or log line ({\"password\":\"x\"}); the value then stops at the
		// next backslash.
		kind:        kindSecret,
		priority:    priorityJSONFragment,
		re:          regexp.MustCompile(`\\?"([A-Za-z0-9_.\- ]{1,64})\\?"\s*:\s*(?:\\"([^"\\\r\n]+)|"((?:[^"\\\r\n]|\\.)+)")`),
		groups:      []int{2, 3},
		prefilter:   []string{"\":", "\": ", "\" :"},
		accept:      keyValueAccept(proseKeyKind, 3),
		jsonEscaped: true,
	},
}

var highEntropyRules = []*rule{
	{
		kind:     "high_entropy",
		priority: priorityHighEntropy,
		set:      setHighEntropy,
		re:       regexp.MustCompile(`[A-Za-z0-9+/_\-]{24,}={0,2}`),
		precheck: hasLongTokenRun,
		accept:   highEntropyAccept,
	},
}

// passwordKeyWords and secretKeyWords classify key names; see secretKeyKind.
var (
	passwordKeyWords = []string{"password", "passwd", "passphrase"}
	secretKeyWords   = []string{
		"secret", "clientsecret", "apikey", "apisecret", "apitoken", "accesstoken",
		"refreshtoken", "authtoken", "idtoken", "bearertoken", "sessiontoken",
		"privatekey", "secretkey", "secretaccesskey", "credential", "credentials",
	}
	// exactPasswordKeys and exactSecretKeys are only secret as a whole key, never as a suffix:
	// "pagetoken" or "bypass" are not credentials.
	exactPasswordKeys = []string{"pwd", "pass", "pin"}
	exactSecretKeys   = []string{"token"}
	// headerKeys hold a whole credential header value ("Bearer ...").
	headerKeys = []string{"authorization", "proxyauthorization", "cookie", "setcookie"}
)

// normalizeKey lower-cases a key name and drops separators, so "client_secret", "clientSecret"
// and "client-secret" compare equal.
func normalizeKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch r {
		case '_', '-', '.', ' ':
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// secretKeyKind reports whether a key name (a JSON member name, a YAML key) is one whose value
// is a credential, and which kind it is.
func secretKeyKind(key string) (string, bool) {
	normalized := normalizeKey(key)
	if normalized == "" || len(normalized) > 64 {
		return "", false
	}
	if slices.Contains(headerKeys, normalized) {
		return "auth_header", true
	}
	words := splitKeyWords(key)
	// "isSecret", "has_password": flags about a secret, not the secret.
	if len(words) > 1 && (words[0] == "IS" || words[0] == "HAS") {
		return "", false
	}
	if slices.Contains(exactPasswordKeys, normalized) {
		return kindPassword, true
	}
	// "db_pass", "dbPwd": pass and pwd count as the last word of a longer name, but not inside
	// one ("bypass").
	if len(words) > 1 && slices.Contains(exactPasswordKeys, strings.ToLower(words[len(words)-1])) {
		return kindPassword, true
	}
	if slices.Contains(exactSecretKeys, normalized) {
		return kindSecret, true
	}
	for _, word := range passwordKeyWords {
		if strings.HasSuffix(normalized, word) {
			return kindPassword, true
		}
	}
	for _, word := range secretKeyWords {
		if strings.HasSuffix(normalized, word) {
			return kindSecret, true
		}
	}
	return "", false
}

// envSecretWords are the words of an environment-variable name that mark its value as a
// credential.
var envSecretWords = map[string]string{
	"PASSWORD": kindPassword, "PASSWD": kindPassword, "PASS": kindPassword, "PASSPHRASE": kindPassword,
	"SECRET": "env_secret", "TOKEN": "env_secret", "APIKEY": "env_secret", "KEY": "env_secret",
	"CREDENTIAL": "env_secret", "CREDENTIALS": "env_secret", "AUTH": "env_secret",
	"DSN": "env_secret", "PRIVATE": "env_secret",
}

// envNonSecretWords, as the last word of a name, mark a value that describes a secret rather
// than holding it (TOKEN_URL, PASSWORD_MIN_LENGTH, KEY_ID).
var envNonSecretWords = map[string]bool{
	"URL": true, "URI": true, "ENDPOINT": true, "HOST": true, "PATH": true, "FILE": true,
	"DIR": true, "TYPE": true, "MODE": true, "ENABLED": true, "ENABLE": true, "EXPIRY": true,
	"EXPIRES": true, "TTL": true, "LENGTH": true, "SIZE": true, "ALGORITHM": true, "ALG": true,
	"NAME": true, "ID": true, "HEADER": true, "PREFIX": true, "PORT": true, "USER": true,
	"USERNAME": true, "LIMIT": true, "COUNT": true, "TIMEOUT": true, "VERSION": true,
	"FORMAT": true, "FIELD": true, "PARAM": true, "SCOPE": true, "SCOPES": true,
	"REGION": true, "ISSUER": true, "AUDIENCE": true, "HINT": true, "METHOD": true,
	"PROVIDER": true, "STRATEGY": true, "BACKEND": true,
}

// envNonSecretKeyQualifiers, right before a final KEY, name a data key rather than a key
// credential (SORT_KEY, PRIMARY_KEY, CACHE_KEY).
var envNonSecretKeyQualifiers = map[string]bool{
	"SORT": true, "PRIMARY": true, "CACHE": true, "PARTITION": true, "FOREIGN": true,
	"ROUTING": true, "HASH": true, "LOOKUP": true, "MAP": true, "OBJECT": true,
	"IDEMPOTENCY": true, "DEDUP": true, "GROUP": true, "SHORTCUT": true, "HOT": true,
}

// splitKeyWords splits FOO_BAR, foo.bar, foo-bar and fooBar into upper-case words.
func splitKeyWords(key string) []string {
	words := make([]string, 0, 4)
	var current []rune
	flush := func() {
		if len(current) > 0 {
			words = append(words, strings.ToUpper(string(current)))
			current = current[:0]
		}
	}
	runes := []rune(key)
	for i, r := range runes {
		if r == '_' || r == '.' || r == '-' {
			flush()
			continue
		}
		if i > 0 && unicode.IsUpper(r) && unicode.IsLower(runes[i-1]) {
			flush()
		}
		current = append(current, r)
	}
	flush()
	return words
}

// envKeyKind classifies an environment-style variable name.
func envKeyKind(key string) (string, bool) {
	words := splitKeyWords(key)
	if len(words) == 0 {
		return "", false
	}
	if upper := strings.ToUpper(key); upper == "PWD" || upper == "OLDPWD" {
		return "", false
	}
	if envNonSecretWords[words[len(words)-1]] || slices.Contains(words, "PUBLIC") {
		return "", false
	}
	if n := len(words); n > 1 && words[n-1] == "KEY" && envNonSecretKeyQualifiers[words[n-2]] {
		return "", false
	}
	for _, word := range words {
		if kind, ok := envSecretWords[word]; ok {
			return kind, true
		}
	}
	return "", false
}

// placeholderValues are values that stand for a credential without being one.
var placeholderValues = map[string]bool{
	"none": true, "null": true, "nil": true, "true": true, "false": true, "undefined": true,
	"empty": true, "n/a": true, "na": true, "redacted": true, "hidden": true, "required": true,
	"optional": true, "unknown": true, "yes": true, "no": true, "not": true, "set": true,
	"unset": true, "expired": true, "invalid": true, "missing": true, "string": true,
	"example": true, "placeholder": true, "your_token": true, "your_password": true,
	"changed": true, "reset": true, "updated": true, "valid": true, "sent": true,
	"enabled": true, "disabled": true, "generated": true, "rotated": true, "revoked": true,
}

// placeholderReference matches a variable reference or a named slot: "$TOKEN",
// "${DB_PASSWORD}", "<your-token>". "$ecretP4ss" is a password.
var placeholderReference = regexp.MustCompile(`^(?:\$\{?[A-Z_][A-Z0-9_]*\}?|\$\{[A-Za-z_][A-Za-z0-9_.]*\}|<[A-Za-z_ \-]+>)$`)

// isPlaceholderValue reports whether a candidate value is obviously not a real secret: too
// short, a variable reference, a template, a mask, or a marker written by redaction.
func isPlaceholderValue(value string) bool {
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) < 3 {
		return true
	}
	if placeholderValues[strings.ToLower(value)] {
		return true
	}
	if strings.Contains(value, "[REDACTED") {
		return true
	}
	if placeholderReference.MatchString(value) || strings.HasPrefix(value, "{{") || strings.HasPrefix(value, "%(") {
		return true
	}
	first, _ := utf8.DecodeRuneInString(value)
	if strings.Trim(value, string(first)) == "" && strings.ContainsRune("*x.•#-_", unicode.ToLower(first)) {
		return true // "*****", "xxxx", "...."
	}
	return false
}

// trimTrailingPunctuation drops sentence punctuation that a greedy unquoted value picked up
// ("password: hunter2." or "(token: abc)").
func trimTrailingPunctuation(text string, start, end int) int {
	for end > start && strings.ContainsRune(".,;:)]}", rune(text[end-1])) {
		end--
	}
	return end
}

// minValueBeforeBreak is the length an unquoted value needs before an escaped line break to end
// there: a part that long is a credential on its own, while a shorter one may be the start of
// a value that holds the break, which is then replaced whole.
const minValueBeforeBreak = 8

// narrowAtBreaks narrows an unquoted value text[start:end] at escaped line breaks and tabs: the
// ones it starts with are dropped when what is left is still a credential, and it ends at the
// first escaped line break when the part before it has at least minValueBeforeBreak characters
// and is a credential. Otherwise the value is kept whole, so the narrowing never lets through
// what the whole value would have replaced.
func narrowAtBreaks(text string, start, end int) (int, int) {
	s := start
	for s < end && (text[s] == maskedBreak || text[s] == maskedTab) {
		s++
	}
	if s > start && s < end && redactedAlone(text, s, end, 0) {
		start = s
	}
	if i := strings.Index(text[start:end], maskedBreakPair); i >= 0 && redactedAlone(text, start, start+i, minValueBeforeBreak) {
		end = start + i
	}
	return start, end
}

// redactedAlone reports whether text[start:end], as keyValueAccept would trim it and without
// surrounding space, has at least
// minRunes characters and is no placeholder, so that it would be replaced on its own.
func redactedAlone(text string, start, end, minRunes int) bool {
	v := strings.TrimSpace(text[start:trimTrailingPunctuation(text, start, end)])
	return utf8.RuneCountInString(v) >= minRunes && !isPlaceholderValue(v)
}

// maskedBreakPair is an escaped line break as the rules see it.
var maskedBreakPair = string([]byte{maskedBreak, maskedBreak})

// keyValueAccept validates a key-value match whose key is in group 1 and whose value is the
// selected span. Groups after quotedGroups hold unquoted values.
func keyValueAccept(classify func(string) (string, bool), quotedGroups int) acceptFunc {
	return func(text string, match []int, start, end int) (int, int, string, bool) {
		key := text[match[2]:match[3]]
		kind, ok := classify(key)
		if !ok {
			return 0, 0, "", false
		}
		// Unquoted values (the last group) can carry trailing punctuation.
		last := len(match)/2 - 1
		if quotedGroups < last && match[2*last] == start {
			start, end = narrowAtBreaks(text, start, end)
			end = trimTrailingPunctuation(text, start, end)
		}
		value := text[start:end]
		if isPlaceholderValue(value) {
			return 0, 0, "", false
		}
		// "pwd" is also the working directory (PWD=/home/user).
		if normalizeKey(key) == "pwd" && (strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~")) {
			return 0, 0, "", false
		}
		return start, end, kind, true
	}
}

// proseKeyKind classifies the key of a "key: value" pair found in free text. It is narrower
// than secretKeyKind: pagination cursors and similar "*_token" names are common in API output
// and are not credentials.
func proseKeyKind(key string) (string, bool) {
	normalized := normalizeKey(key)
	for _, word := range []string{"page", "cursor", "sync", "next", "csrf", "continuation"} {
		if strings.Contains(normalized, word) {
			return "", false
		}
	}
	return secretKeyKind(key)
}

// acceptAll accepts every candidate of rules whose shape is specific enough.
func acceptAll(_ string, _ []int, start, end int) (int, int, string, bool) {
	return start, end, "", true
}

func rejectPlaceholder(text string, _ []int, start, end int) (int, int, string, bool) {
	if isPlaceholderValue(text[start:end]) {
		return 0, 0, "", false
	}
	return start, end, "", true
}

func isTokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// hasDigitColonRun reports whether text has a digit, a colon and 35 token characters in a row,
// the shape of a Telegram bot token.
func hasDigitColonRun(text string) bool {
	for i := 1; i < len(text); i++ {
		if text[i] != ':' || text[i-1] < '0' || text[i-1] > '9' {
			continue
		}
		run := 0
		for j := i + 1; j < len(text) && isTokenByte(text[j]); j++ {
			run++
		}
		if run >= 35 {
			return true
		}
	}
	return false
}

// hasURLUserinfo reports whether some "://" is followed by an "@" before the URL's host part
// ends.
func hasURLUserinfo(text string) bool {
	for offset := 0; ; {
		i := strings.Index(text[offset:], "://")
		if i < 0 {
			return false
		}
		start := offset + i + 3
		for j := start; j < len(text); j++ {
			c := text[j]
			if c == '@' {
				return true
			}
			if c == '/' || c == ' ' || c == '\n' || c == '\t' || c == '"' || c == '?' || c == '#' {
				break
			}
		}
		offset = start
	}
}

// hasLongTokenRun reports whether text has 24 base64-ish characters in a row.
func hasLongTokenRun(text string) bool {
	run := 0
	for i := range len(text) {
		if c := text[i]; isTokenByte(c) || c == '+' || c == '/' {
			run++
			if run >= 24 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// entropyContextWindow bounds how far highEntropyAccept looks around a token.
const entropyContextWindow = 256

// minTokenEntropy is the Shannon entropy, in bits per byte, a high-entropy token needs.
const minTokenEntropy = 4.0

// highEntropyAccept keeps a token that looks randomly generated: mixed case and digits, enough
// Shannon entropy, and not part of a path or URL (resource names such as
// "spaces/AAAA/messages/BBBB" are long and random too).
func highEntropyAccept(text string, _ []int, start, end int) (int, int, string, bool) {
	token := text[start:end]
	if start > 0 && strings.ContainsRune("/.@\\", rune(text[start-1])) {
		return 0, 0, "", false
	}
	if end < len(text) && strings.ContainsRune("/@\\", rune(text[end])) {
		return 0, 0, "", false
	}
	// A lower-case word between slashes marks a path or resource name
	// ("spaces/AAAA/messages/BBBB"), which base64 almost never produces.
	if strings.Contains(token, "/") {
		for segment := range strings.SplitSeq(token, "/") {
			if len(segment) >= 3 && strings.IndexFunc(segment, func(r rune) bool { return r < 'a' || r > 'z' }) < 0 {
				return 0, 0, "", false
			}
		}
	}
	// Look around only within a bounded window, so text without whitespace cannot make each
	// candidate scan the whole input.
	windowStart := max(0, start-entropyContextWindow)
	windowEnd := min(len(text), end+entropyContextWindow)
	wordStart := windowStart + strings.LastIndexAny(text[windowStart:start], " \t\r\n\"'") + 1
	wordEnd := windowEnd
	if i := strings.IndexAny(text[end:windowEnd], " \t\r\n\"'"); i >= 0 {
		wordEnd = end + i
	}
	if strings.Contains(text[wordStart:wordEnd], "://") {
		return 0, 0, "", false
	}
	// SSH public keys ("ssh-ed25519 AAAAC3...") are long base64 but public.
	before := strings.TrimRight(text[windowStart:start], " \t")
	if i := strings.LastIndexAny(before, " \t\r\n\"'") + 1; strings.HasPrefix(before[i:], "ssh-") ||
		strings.HasPrefix(before[i:], "ecdsa-sha2-") || strings.HasPrefix(before[i:], "sk-ssh-") || strings.HasPrefix(before[i:], "sk-ecdsa-") {
		return 0, 0, "", false
	}
	var upper, lower, digit bool
	for _, r := range token {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !upper || !lower || !digit {
		return 0, 0, "", false // hex digests, lower-case ids, words
	}
	if shannonEntropy(token) < minTokenEntropy {
		return 0, 0, "", false
	}
	return start, end, "", true
}

func shannonEntropy(s string) float64 {
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	entropy := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
