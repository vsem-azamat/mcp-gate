package redact

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRussianLabels(t *testing.T) {
	t.Parallel()

	positives := map[string]string{
		"Пароль: Summer-Blue-77!":                                   "Summer-Blue-77!",
		"пароль — qwerty123":                                        "qwerty123",
		"вот пароль Zx9-kL2m":                                       "Zx9-kL2m",
		"токен: abcdef123456":                                       "abcdef123456",
		"Ключ = AbCdEf-998877":                                      "AbCdEf-998877",
		"логин/пароль: admin / Qwerty123":                           "Qwerty123",
		"логин и пароль - root:toor-77":                             "toor-77",
		"Пароль\u200b: hunter22":                                    "hunter22",
		"пароль: «correct horse battery 9»":                         "correct horse battery 9",
		"секрет: s3cr3t-value":                                      "s3cr3t-value",
		"код доступа: 774411":                                       "774411",
		"апи ключ: zz-top-secret-1":                                 "zz-top-secret-1",
		"ПАРОЛЬ: Upper-Case-1":                                      "Upper-Case-1",
		"не забудь, пароль: tr1cky.":                                "tr1cky",
		"пароль от wifi: wifi-Pass-2026":                            "wifi-Pass-2026",
		"ключа нет, токен: xyz-123-abc-tail":                        "xyz-123-abc-tail",
		"пароль от почты: mail-Pw-1":                                "mail-Pw-1",
		"пароль к wifi — Wifi2026x":                                 "Wifi2026x",
		"Пароль:\nNextLine-77":                                      "NextLine-77",
		`Логин: bob\nПароль: escaped-Nl-77`:                         "escaped-Nl-77",
		"Пароли: first-Pw-1":                                        "first-Pw-1",
		"ключ доступа: acc-key-9911":                                "acc-key-9911",
		"пароль -- dash-Pw-2":                                       "dash-Pw-2",
		"пароль: `tick-Pw-3`":                                       "tick-Pw-3",
		"логин/пароль: admin / Qwerty123, ключ " + fake("AKIA", 16): "Qwerty123",
	}
	negatives := []string{
		"пароль был изменён",
		"токен истёк",
		"токен: истёк",
		"ключ от квартиры у соседа",
		"ключ: в верхнем ящике",
		"Обычное сообщение без доступов",
		"пароль: ********",
		"пароль: нет",
		"ключевой момент: завтра",
		"токен USDT-TRC20",
		"токен ERC-20",
		"ключ ssh-rsa",
		"ключ: ED25519",
		"ключ — 2048 бит",
		"ключ - 12:30",
		"секрет: 50%",
		"токен — Telegram выдаёт",
		"логин/пароль - пришлю позже в личку",
		"пароль от почты сменили",
	}
	for _, highEntropy := range []bool{false, true} {
		e := newEngine(t, Options{Russian: true, HighEntropy: highEntropy})
		for text, secret := range positives {
			if got := e.RedactString(text, Marker{}); strings.Contains(got, secret) || !strings.Contains(got, markerPrefix) {
				t.Errorf("highEntropy=%v: %q -> %q, secret survived", highEntropy, text, got)
			}
		}
		for _, text := range negatives {
			if got := e.RedactString(text, Marker{}); got != text {
				t.Errorf("highEntropy=%v: %q changed to %q", highEntropy, text, got)
			}
		}
	}

	// Without Options.Russian the labels are ordinary words.
	e := newEngine(t, Options{})
	for _, text := range []string{"Пароль: Summer-Blue-77!", "токен: abcdef123456", "логин/пароль: admin / Qwerty123"} {
		if got := e.RedactString(text, Marker{}); got != text {
			t.Errorf("Russian off: %q changed to %q", text, got)
		}
	}
}

// The rule order is part of the behaviour: the earlier rule gives its kind to an overlap. It
// is the same whatever the options.
func TestRuleOrder(t *testing.T) {
	t.Parallel()

	want := []struct {
		kind string
		set  ruleSet
	}{
		{"password", setRussian}, // the login/password pair
		{"private_key", setCore},
		{"aws_access_key", setCore},
		{"aws_secret_key", setCore},
		{"github_token", setCore},
		{"gitlab_token", setCore},
		{"anthropic_api_key", setCore},
		{"openai_api_key", setCore},
		{"google_api_key", setCore},
		{"google_oauth_token", setCore},
		{"slack_token", setCore},
		{"slack_webhook", setCore},
		{"telegram_bot_token", setCore},
		{"stripe_key", setCore},
		{"jwt", setCore},
		{"auth_header", setCore},
		{"url_password", setCore},
		{"env_secret", setCore},
		{"secret", setCore}, // key: value
		{"secret", setCore}, // key: and the value on the next line
		{"secret", setCore}, // --flag value
		{"secret", setCore}, // "key": "value" fragment
		{"high_entropy", setHighEntropy},
		{"password", setRussian}, // the Russian label
	}
	e := newEngine(t, Options{Russian: true, HighEntropy: true})
	if len(e.rules) != len(want) {
		t.Fatalf("%d rules, want %d", len(e.rules), len(want))
	}
	for i, r := range e.rules {
		if r.kind != want[i].kind || r.set != want[i].set {
			t.Errorf("rule %d is %s (set %d), want %s (set %d)", i, r.kind, r.set, want[i].kind, want[i].set)
		}
	}
	// Turning a set off removes its rules and keeps the others in the same order.
	core := newEngine(t, Options{})
	var wantCore []*rule
	for _, r := range e.rules {
		if r.set == setCore {
			wantCore = append(wantCore, r)
		}
	}
	if !slices.Equal(core.rules, wantCore) {
		t.Error("core rules differ in order without the optional sets")
	}
}

func TestSortRulesRejectsDuplicatePriorities(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("sortRules accepted two rules with one priority")
		}
	}()
	sortRules([]*rule{{kind: "a", priority: 1}, {kind: "b", priority: 1}})
}

func TestPriorityDecidesOverlaps(t *testing.T) {
	t.Parallel()

	// The pair rule runs first, so the AWS key later on its line cannot split it: the whole
	// rest of the line is one password.
	awsKey := "AKIA" + "ABCDEFGHIJKLMNOP"
	text := "логин/пароль: admin / Qwerty123, ключ " + awsKey
	spans := newEngine(t, Options{Russian: true}).Find(text)
	if len(spans) != 1 || spans[0].Finding.Kind != "password" || spans[0].Finding.Value != "admin / Qwerty123, ключ "+awsKey {
		t.Fatalf("Russian on: spans = %+v", spans)
	}
	spans = newEngine(t, Options{}).Find(text)
	if len(spans) != 1 || spans[0].Finding.Kind != "aws_access_key" {
		t.Fatalf("Russian off: spans = %+v", spans)
	}

	// The high-entropy rule runs before the Russian label rule and gives its kind to the value.
	e := newEngine(t, Options{Russian: true, HighEntropy: true})
	spans = e.Find("токен: " + fake("", 32))
	if len(spans) != 1 || spans[0].Finding.Kind != "high_entropy" {
		t.Fatalf("spans = %+v", spans)
	}

	// A vendor format gives its kind to the generic key-value match around it.
	spans = newEngine(t, Options{}).Find("token: " + fake("ghp_", 36))
	if len(spans) != 1 || spans[0].Finding.Kind != "github_token" {
		t.Fatalf("spans = %+v", spans)
	}
}

func TestOverlappingFindingsAreMerged(t *testing.T) {
	t.Parallel()

	token := fake("ghp_", 36)
	tests := []struct {
		name, text, want string
		value            string
	}{
		{
			// The unquoted password value runs into the token; the token's rule runs first.
			name:  "password running into a token",
			text:  "password: hunter22," + token,
			want:  "password: [REDACTED:github_token]",
			value: "hunter22," + token,
		},
		{
			// An unquoted value ends at an escaped line break, so the two stay apart.
			name:  "password and token across an escaped newline",
			text:  `password: hunter22\n` + token + " tail",
			want:  `password: [REDACTED:password]\n[REDACTED:github_token] tail`,
			value: "hunter22",
		},
		{
			name: "one value over two higher-priority findings",
			// The AWS key is split so that secret scanners do not flag the literal.
			text:  "password: " + token + "," + "AKIA" + "ABCDEFGHIJKLMNOP!",
			want:  "password: [REDACTED:aws_access_key]", // the AWS rule has the lowest number
			value: token + "," + "AKIA" + "ABCDEFGHIJKLMNOP!",
		},
		{
			name:  "adjacent findings stay apart",
			text:  token + " password: hunter22",
			want:  "[REDACTED:github_token] password: [REDACTED:password]",
			value: token,
		},
	}
	e := newEngine(t, Options{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := e.RedactString(tt.text, Marker{}); got != tt.want {
				t.Errorf("RedactString = %q, want %q", got, tt.want)
			}
			spans := e.Find(tt.text)
			if len(spans) == 0 || spans[0].Finding.Value != tt.value || tt.text[spans[0].Start:spans[0].End] != tt.value {
				t.Errorf("first span = %+v, want value %q", spans, tt.value)
			}
		})
	}
}

func TestMergeSpans(t *testing.T) {
	t.Parallel()

	sp := func(start, end, priority int, escaped bool) span {
		return span{start: start, end: end, kind: fmt.Sprint("k", priority), priority: priority, jsonEscaped: escaped}
	}
	tests := []struct {
		name        string
		kept, added []span
		want        []span
	}{
		{"touching spans stay apart", []span{sp(0, 5, 1, false)}, []span{sp(5, 9, 2, false)}, []span{sp(0, 5, 1, false), sp(5, 9, 2, false)}},
		{"added inside kept", []span{sp(0, 9, 1, true)}, []span{sp(2, 4, 2, false)}, []span{sp(0, 9, 1, true)}},
		{"added starts first", []span{sp(4, 9, 1, false)}, []span{sp(0, 6, 2, false)}, []span{sp(0, 9, 1, false)}},
		{"added bridges two kept", []span{sp(0, 3, 2, false), sp(6, 9, 1, false)}, []span{sp(2, 7, 3, false)}, []span{sp(0, 9, 1, false)}},
		{"kept bridges two added", []span{sp(2, 7, 1, false)}, []span{sp(0, 3, 2, false), sp(6, 9, 2, false)}, []span{sp(0, 9, 1, false)}},
		{"equal starts", []span{sp(0, 4, 1, false)}, []span{sp(0, 8, 2, false)}, []span{sp(0, 8, 1, false)}},
		{"escaped winner over a wider union is raw", []span{sp(2, 4, 1, true)}, []span{sp(0, 8, 2, false)}, []span{sp(0, 8, 1, false)}},
		{"escaped winner covering the union stays decoded", []span{sp(0, 8, 1, true)}, []span{sp(2, 4, 2, false)}, []span{sp(0, 8, 1, true)}},
		{"escaped loser covering the union is decoded", []span{sp(2, 4, 1, false)}, []span{sp(0, 8, 2, true)}, []span{sp(0, 8, 1, true)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mergeSpans(tt.kept, tt.added); !slices.Equal(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
	// A chain over three rounds collapses into one span with the first round's kind.
	got := mergeSpans(mergeSpans([]span{sp(0, 3, 1, false)}, []span{sp(2, 6, 2, false)}), []span{sp(5, 9, 3, false)})
	if want := []span{sp(0, 9, 1, false)}; !slices.Equal(got, want) {
		t.Errorf("chain: got %+v, want %+v", got, want)
	}
}

func TestMergedValueIsRawOutsideALiteral(t *testing.T) {
	t.Parallel()

	// The JSON-fragment finding is escaped, the wider Russian label finding is not; the merged
	// value is the text as written.
	text := `пароль «\"pwd\":\"abc\" x\t y»`
	spans := newEngine(t, Options{Russian: true}).Find(text)
	if len(spans) != 1 || spans[0].Finding.Value != text[spans[0].Start:spans[0].End] {
		t.Fatalf("spans = %+v", spans)
	}
}

func TestMergedValueInsideALiteralIsDecoded(t *testing.T) {
	t.Parallel()

	token := fake("ghp_", 36)
	spans := newEngine(t, Options{}).Find(`log "password":"a\u0041b,` + token + `" end`)
	if len(spans) != 1 || spans[0].Finding.Kind != "github_token" || spans[0].Finding.Value != "aAb,"+token {
		t.Fatalf("spans = %+v", spans)
	}
}

// Overlapping findings from several rules and whitespace-free input must stay linear. Not
// parallel, so that other tests do not slow it down.
func TestLargeInputsStayFast(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	// About 1.5 MB each; the race detector slows the scan about twenty times, so it gets a
	// tenth. A quadratic scan takes minutes at either size.
	repeat, limit := 40000, 3*time.Second
	if raceEnabled {
		repeat, limit = 4000, 10*time.Second
	}
	inputs := []string{
		strings.Repeat("password: hunter2secret\nAKIAABCDEFGHIJKLMNOP\n", repeat),
		strings.Repeat("Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0,", repeat),
	}
	e := newEngine(t, Options{Russian: true, HighEntropy: true})
	for _, text := range inputs {
		start := time.Now()
		_ = e.RedactString(text, Marker{})
		if elapsed := time.Since(start); elapsed > limit {
			t.Errorf("%d bytes took %v", len(text), elapsed)
		}
	}
}
