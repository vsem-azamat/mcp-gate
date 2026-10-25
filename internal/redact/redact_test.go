package redact

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fake builds a made-up secret at run time, so that no token-shaped literal sits in the source,
// where secret scanners would (rightly) flag it.
func fake(prefix string, n int) string {
	const alphabet = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
	var b strings.Builder
	b.WriteString(prefix)
	for i := range n {
		b.WriteByte(alphabet[(i*7+3)%len(alphabet)])
	}
	return b.String()
}

func newEngine(t testing.TB, opts Options) *Engine {
	t.Helper()
	e, err := New(opts)
	if err != nil {
		t.Fatalf("New(%+v): %v", opts, err)
	}
	return e
}

// optionSets are the option combinations every core test runs under.
var optionSets = []Options{{}, {Russian: true}, {HighEntropy: true}, {Russian: true, HighEntropy: true}}

func TestFindsKnownSecretFormats(t *testing.T) {
	t.Parallel()

	pem := "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + fake("", 40) + "\n-----END RSA PRIVATE KEY-----"
	jwt := "eyJ" + fake("", 20) + ".eyJ" + fake("", 30) + "." + fake("", 43)
	tests := []struct {
		name   string
		text   string
		secret string
		kind   string
	}{
		{name: "pem private key", text: "key:\n" + pem + "\nthanks", secret: "MIIEowIBAAKCAQEA", kind: "private_key"},
		{name: "truncated pem", text: "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA" + fake("", 30), secret: "b3BlbnNzaC1rZXktdjEAAAAA", kind: "private_key"},
		{name: "aws access key", text: "id " + fake("AKIA", 0) + "IOSFODNN7EXAMPLE ok", secret: "IOSFODNN7EXAMPLE", kind: "aws_access_key"},
		{name: "aws secret key", text: "aws_secret_access_key = " + fake("", 40), secret: fake("", 40), kind: "aws_secret_key"},
		{name: "github classic", text: "use " + fake("ghp_", 36), secret: fake("ghp_", 36), kind: "github_token"},
		{name: "github fine-grained", text: fake("github_pat_", 60), secret: fake("github_pat_", 60), kind: "github_token"},
		{name: "gitlab", text: "token " + fake("glpat-", 20), secret: fake("glpat-", 20), kind: "gitlab_token"},
		{name: "anthropic", text: fake("sk-ant-api03-", 80), secret: fake("sk-ant-api03-", 80), kind: "anthropic_api_key"},
		{name: "openai project", text: "key " + fake("sk-proj-", 64), secret: fake("sk-proj-", 64), kind: "openai_api_key"},
		{name: "google api key", text: fake("AIza", 35), secret: fake("AIza", 35), kind: "google_api_key"},
		{name: "google oauth access", text: fake("ya29.", 60), secret: fake("ya29.", 60), kind: "google_oauth_token"},
		{name: "slack bot", text: fake("xoxb-", 40), secret: fake("xoxb-", 40), kind: "slack_token"},
		{name: "slack webhook", text: "post to https://hooks.slack.com/services/" + fake("T", 10) + "/" + fake("B", 10) + "/" + fake("", 24), secret: fake("", 24), kind: "slack_webhook"},
		{name: "stripe", text: "key " + fake("sk_"+"live_", 24), secret: fake("sk_"+"live_", 24), kind: "stripe_key"},
		{name: "telegram bot", text: "bot token 123456789:" + fake("AA", 33) + " here", secret: fake("AA", 33), kind: "telegram_bot_token"},
		{name: "telegram bot after an escaped newline", text: `Use this token to access the HTTP API:\n7123456789:` + fake("AA", 33) + `\nKeep it secure`, secret: fake("AA", 33), kind: "telegram_bot_token"},
		{name: "second of two telegram bots", text: "A=7123456789:" + fake("AA", 33) + " B=8123456789:" + fake("BB", 33), secret: fake("BB", 33), kind: "telegram_bot_token"},
		{name: "github token after an escaped newline", text: `see:\n` + fake("ghp_", 36), secret: fake("ghp_", 36), kind: "github_token"},
		{name: "aws key after an escaped tab", text: `id:\t` + fake("AKIA", 0) + "IOSFODNN7EXAMPLE", secret: "IOSFODNN7EXAMPLE", kind: "aws_access_key"},
		{name: "token label after an escaped newline", text: `user\nToken: hunter22secret`, secret: "hunter22secret", kind: "secret"},
		{name: "quoted value ending in an escaped newline", text: `password: "hunter22secret\n"`, secret: "hunter22secret", kind: "password"},
		{name: "repr value ending in an escaped newline", text: `{'password': 'hunter22secret\n', 'user': 'bob'}`, secret: "hunter22secret", kind: "password"},
		{name: "json fragment ending in an escaped newline", text: `log {"client_secret": "hunter22secret\n"} tail`, secret: "hunter22secret", kind: "secret"},
		{name: "env value ending in an escaped newline", text: `DB_PASSWORD="hunter22secret\n"`, secret: "hunter22secret", kind: "password"},
		{name: "quoted value with an escaped newline inside", text: `password: "Xk9\nP2qZ7"`, secret: "P2qZ7", kind: "password"},
		{name: "unquoted value with an escaped tab inside", text: `password: Qw\terty77`, secret: "erty77", kind: "password"},
		{name: "bearer after an escaped crlf", text: `hdr\r\nAuthorization: Bearer ` + fake("", 30), secret: fake("", 30), kind: "auth_header"},
		{name: "jwt", text: "Cookie: session=" + jwt, secret: jwt, kind: "jwt"},
		{name: "authorization header", text: "Authorization: Bearer " + fake("", 30), secret: fake("", 30), kind: "auth_header"},
		{name: "url credentials", text: "DATABASE=postgres://app:s3cr3t-Pa55@db.example.com:5432/app", secret: "s3cr3t-Pa55", kind: "url_password"},
		{name: "env password", text: "DB_HOST=db\nDB_PASSWORD=hunter2!x\n", secret: "hunter2!x", kind: "password"},
		{name: "env export quoted", text: `export MY_API_KEY="abc 123 def"`, secret: "abc 123 def", kind: "env_secret"},
		{name: "env lower-case", text: "smtp_pass=Pa55word-1 # rotated", secret: "Pa55word-1", kind: "password"},
		{name: "prose password", text: "the password: Summer-Blue-77! ok", secret: "Summer-Blue-77!", kind: "password"},
		{name: "prose pwd", text: "login admin pwd=hunter22.", secret: "hunter22", kind: "password"},
		{name: "prose api key", text: "set api_key = zz9plural now", secret: "zz9plural", kind: "secret"},
		{name: "prose token", text: "token: abcdef0123456789", secret: "abcdef0123456789", kind: "secret"},
		{name: "fullwidth colon", text: "password：fullwidth1", secret: "fullwidth1", kind: "password"},
		{name: "zero-width before colon", text: "password\u200b: hunter22", secret: "hunter22", kind: "password"},
		{name: "yaml", text: "db:\n  password: \"quoted secret\"\n", secret: "quoted secret", kind: "password"},
		{name: "query string", text: "GET /cb?code=1&access_token=qwertyuiop&x=1", secret: "qwertyuiop", kind: "secret"},
		{name: "json fragment in prose", text: `config was {"client_secret": "cs-123456"} oops`, secret: "cs-123456", kind: "secret"},
		{name: "escaped json in a log line", text: `log: {\"password\":\"esc-aped-1\"}`, secret: "esc-aped-1", kind: "password"},
		{name: "prefixed yaml key", text: "  MYSQL_ROOT_PASSWORD: rootpw-77", secret: "rootpw-77", kind: "password"},
		{name: "camel case key", text: "userPassword: camel-pw-1", secret: "camel-pw-1", kind: "password"},
		{name: "inline env", text: "run PGPASSWORD=pgpw-123 psql", secret: "pgpw-123", kind: "password"},
		{name: "go assignment", text: `password := "go-assign-1"`, secret: "go-assign-1", kind: "password"},
		{name: "php arrow", text: `'password' => 'arrow-pw-1'`, secret: "arrow-pw-1", kind: "password"},
		{name: "spaced key", text: "API key: spaced-key-123", secret: "spaced-key-123", kind: "secret"},
		{name: "cli flag", text: "mysql --password hunter-cli-2 db", secret: "hunter-cli-2", kind: "password"},
		{name: "redis empty user", text: "redis://:redis-pw@cache:6379", secret: "redis-pw", kind: "url_password"},
		{name: "at sign in url password", text: "postgres://u:p@ss-word@db/x", secret: "p@ss-word", kind: "url_password"},
		{name: "dollar password", text: "password=$ecretP4ss", secret: "$ecretP4ss", kind: "password"},
		{name: "nbsp before colon", text: "password\u00a0: nbsp-pw-1", secret: "nbsp-pw-1", kind: "password"},
	}
	for _, opts := range optionSets {
		e := newEngine(t, opts)
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%+v/%s", opts, tt.name), func(t *testing.T) {
				t.Parallel()
				got := e.RedactString(tt.text, Marker{})
				if strings.Contains(got, tt.secret) {
					t.Fatalf("secret survived: %q", got)
				}
				if !strings.Contains(got, MarkerText(tt.kind)) {
					t.Fatalf("want marker %s in %q", MarkerText(tt.kind), got)
				}
				if again := e.RedactString(got, Marker{}); again != got {
					t.Fatalf("a second pass changed %q to %q", got, again)
				}
			})
		}
	}
}

func TestLeavesOrdinaryTextAlone(t *testing.T) {
	t.Parallel()

	texts := []string{
		"commit 8f14e45fceea167a5a36dedd4bea2543 merged",
		"sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"550e8400-e29b-41d4-a716-446655440000",
		"spaces/AAAAx7KqL2w/messages/Zr4TbW9mQe1.Zr4TbW9mQe1",
		"Build 123456 completed on 2026-08-31",
		"token count is 123",
		`path C:\\new\\tokens\\list.txt`,
		"the password was changed yesterday",
		"Token: none",
		"password: ********",
		"PASSWORD=${DB_PASSWORD}",
		"TOKEN_URL=https://auth.example.com/token",
		"PASSWORD_MIN_LENGTH=12",
		"KEYBOARD=us",
		"PWD=/home/user/project",
		"API_KEY_ID=12345",
		"https://example.com/path?page=2&sort=asc",
		"mail user@example.com about it",
		"bypass: yes",
		"compass: north",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + fake("", 43) + " user@example.com",
		`{"nextPageToken":"CAESBggBEAEYAQ","pageSize":50}`,
		"next_page_token: CAESBggBEAEYAQ",
		"Привет, как дела?",
		"SORT_KEY=created_at",
		"PRIMARY_KEY=id",
		"AUTH_METHOD=oauth",
		`{"isSecret":"maybe","has_password":"yes"}`,
		"see the API reference: https://example.com/api",
		"Password: changed yesterday",
		"Token: valid until Friday",
	}
	for _, opts := range optionSets {
		e := newEngine(t, opts)
		for _, text := range texts {
			if got := e.RedactString(text, Marker{}); got != text {
				t.Errorf("%+v: %q was changed to %q", opts, text, got)
			}
		}
	}
}

func TestExactOutput(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{})
	for text, want := range map[string]string{
		"the password: Summer-Blue-77! ok":                "the password: [REDACTED:password] ok",
		"login admin pwd=hunter22.":                       "login admin pwd=[REDACTED:password].",
		"db_pass: pw-last-word\ndbPwd: pw-camel-77":       "db_pass: [REDACTED:password]\ndbPwd: [REDACTED:password]",
		"Authorization: Bearer " + fake("", 30) + " tail": "Authorization: Bearer [REDACTED:auth_header] tail",
	} {
		if got := e.RedactString(text, Marker{}); got != want {
			t.Errorf("%q -> %q, want %q", text, got, want)
		}
	}
}

func TestPlaceholdersAreNotSecrets(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{Russian: true, HighEntropy: true})
	for _, value := range []string{"{{ .Token }}", "%(password)s", "<your-token>", "xxxx", "$TOKEN", "${DB_PASSWORD}", "ab", "redacted", "[REDACTED:password]", "•••••"} {
		for _, text := range []string{"password: " + value, `{"password":"` + value + `"}`} {
			if got := e.RedactString(text, Marker{}); got != text {
				t.Errorf("%q changed to %q", text, got)
			}
		}
	}
}

func TestHeaderMembers(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{})
	doc := `{"Proxy-Authorization":"Basic abc123def","Cookie":"sid=abc123def","set-cookie":"sid=abc123def","db_token":"abc123def"}`
	want := `{"Proxy-Authorization":"[REDACTED:auth_header]","Cookie":"[REDACTED:auth_header]","set-cookie":"[REDACTED:auth_header]","db_token":"abc123def"}`
	if got := e.RedactString(doc, Marker{}); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestHighEntropyIsOptIn(t *testing.T) {
	t.Parallel()

	text := "here is " + fake("", 32) + " for you"
	if got := newEngine(t, Options{}).RedactString(text, Marker{}); got != text {
		t.Fatalf("highEntropy off changed %q to %q", text, got)
	}
	got := newEngine(t, Options{HighEntropy: true}).RedactString(text, Marker{})
	if strings.Contains(got, fake("", 32)) || !strings.Contains(got, MarkerText("high_entropy")) {
		t.Fatalf("highEntropy on: got %q", got)
	}
}

func TestDisableRules(t *testing.T) {
	t.Parallel()

	jwt := "eyJ" + fake("", 20) + ".eyJ" + fake("", 30) + "." + fake("", 43)
	text := "a " + jwt + " password: hunter22"
	e := newEngine(t, Options{DisableRules: []string{"jwt", "password"}})
	if got := e.RedactString(text, Marker{}); got != text {
		t.Fatalf("disabled rules still applied: %q", got)
	}
	// A disabled kind is not reported under a secret JSON member either.
	doc := `{"password":"hunter22","pin":12345}`
	if got := e.RedactString(doc, Marker{}); got != doc {
		t.Fatalf("disabled kind replaced in JSON: %s", got)
	}
}

func TestNewRejectsUnknownRule(t *testing.T) {
	t.Parallel()

	_, err := New(Options{DisableRules: []string{"jwt", "nope", "password", "also-nope"}})
	if err == nil {
		t.Fatal("unknown rules accepted")
	}
	for _, want := range []string{`disableRules[1]: unknown rule "nope"`, `disableRules[3]: unknown rule "also-nope"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if _, err := New(Options{DisableRules: Kinds()}); err != nil {
		t.Errorf("every kind from Kinds must be accepted: %v", err)
	}
}

func TestKinds(t *testing.T) {
	t.Parallel()

	want := []string{
		"anthropic_api_key", "auth_header", "aws_access_key", "aws_secret_key", "env_secret",
		"github_token", "gitlab_token", "google_api_key", "google_oauth_token", "high_entropy",
		"jwt", "openai_api_key", "password", "private_key", "secret", "slack_token",
		"slack_webhook", "stripe_key", "telegram_bot_token", "url_password",
	}
	if got := Kinds(); !slices.Equal(got, want) {
		t.Fatalf("Kinds() = %q, want %q", got, want)
	}
}

func TestJSONTextIsRewrittenValueByValue(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{Russian: true})
	tests := []struct {
		name    string
		text    string
		secrets []string
		keep    []string
	}{
		{
			name:    "message text with escaped newline",
			text:    `{"messages":[{"id":42,"text":"password: hunter22\nsee you"}]}`,
			secrets: []string{"hunter22"},
			keep:    []string{`"id":42`, `\nsee you`},
		},
		{
			name:    "unicode-escaped label",
			text:    `{"text":"\u0070assword: hunter22"}`,
			secrets: []string{"hunter22"},
		},
		{
			name:    "secret member names",
			text:    `{"client_secret":"abc123def","dbPassword":"zzz999","nextPageToken":"CAESBggB","token_count":5}`,
			secrets: []string{"abc123def", "zzz999"},
			keep:    []string{`"nextPageToken":"CAESBggB"`, `"token_count":5`},
		},
		{
			name:    "array under secret member",
			text:    `{"token":["one-secret","two-secret"]}`,
			secrets: []string{"one-secret", "two-secret"},
		},
		{
			name:    "json nested in a string",
			text:    `{"result":"{\"password\":\"hunter22\"}"}`,
			secrets: []string{"hunter22"},
		},
		{
			name:    "authorization header member",
			text:    `{"headers":{"Authorization":"Bearer abcdefgh12345678","Accept":"*/*"}}`,
			secrets: []string{"abcdefgh12345678"},
			keep:    []string{`"Accept":"*/*"`},
		},
		{
			name:    "numeric secret member",
			text:    `{"password": 12345678, "count": 12345678, "pin": 12}`,
			secrets: []string{`"password": 12345678`},
			keep:    []string{`"password": "[REDACTED:password]"`, `"count": 12345678`, `"pin": 12`},
		},
		{
			name:    "dollar value under secret member",
			text:    `{"password":"$ecretP4ss"}`,
			secrets: []string{"$ecretP4ss"},
		},
		{
			name:    "object under a secret member",
			text:    `{"token":{"access":"abcdef123","refresh":"ghijkl456","type":"Bearer","expires_in":3600},"credentials":"{\"user\":\"bob\",\"value\":\"hunter2secret\"}"}`,
			secrets: []string{"abcdef123", "ghijkl456", "hunter2secret"},
			keep:    []string{`"type":"Bearer"`, `"expires_in":3600`, `bob`},
		},
		{
			name:    "json array string under a secret member",
			text:    `{"password":"[\"hunter2secret\"]"}`,
			secrets: []string{"hunter2secret"},
		},
		{
			name:    "placeholder under a secret member",
			text:    `{"password":"********","token":null}`,
			keep:    []string{`{"password":"********","token":null}`},
			secrets: []string{"REDACTED"},
		},
		{
			name: "key order and spacing preserved",
			text: "{\n  \"z\": 1,\n  \"a\": \"password: hunter22\"\n}",
			keep: []string{"{\n  \"z\": 1,\n  \"a\": \"password: [REDACTED:password]\"\n}"},
		},
		{
			name: "russian label inside json",
			text: `{"messages":[{"text":"пароль: Qwerty-12345"}]}`,
			keep: []string{`{"messages":[{"text":"пароль: [REDACTED:password]"}]}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := e.RedactString(tt.text, Marker{})
			if !json.Valid([]byte(got)) {
				t.Fatalf("result is not valid JSON: %s", got)
			}
			for _, secret := range tt.secrets {
				if strings.Contains(got, secret) {
					t.Errorf("%q survived: %s", secret, got)
				}
			}
			for _, keep := range tt.keep {
				if !strings.Contains(got, keep) {
					t.Errorf("want %q kept in %s", keep, got)
				}
			}
		})
	}
}

func TestRedactJSON(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{})
	got, err := e.RedactJSON([]byte(` {"b":2, "note":"password: hunter22", "a":[1,2]} `), Marker{})
	if err != nil {
		t.Fatal(err)
	}
	if want := ` {"b":2, "note":"password: [REDACTED:password]", "a":[1,2]} `; string(got) != want {
		t.Errorf("RedactJSON = %s, want %s", got, want)
	}
	for _, bad := range []string{``, `{`, `{"a":1}x`, `password: hunter22`} {
		if out, err := e.RedactJSON([]byte(bad), Marker{}); err == nil || out != nil {
			t.Errorf("RedactJSON(%q) = %q, %v; want ErrInvalidJSON", bad, out, err)
		}
	}
	// Strings that hold JSON are followed five levels deep; below that they are matched as
	// text, where the JSON-fragment rule still finds an escaped member.
	nested := `{"password":"hunter22"}`
	for range 5 {
		raw, err := json.Marshal(map[string]string{"x": nested})
		if err != nil {
			t.Fatal(err)
		}
		nested = string(raw)
	}
	out, err := e.RedactJSON([]byte(nested), Marker{})
	if err != nil || strings.Contains(string(out), "hunter22") || !json.Valid(out) {
		t.Errorf("deeply nested secret: %s, %v", out, err)
	}
	// Only the JSON rewrite finds a numeric password, so this one shows nesting is followed.
	nested = `{"password":12345678}`
	for range 4 {
		raw, err := json.Marshal(map[string]string{"x": nested})
		if err != nil {
			t.Fatal(err)
		}
		nested = string(raw)
	}
	if out, err := e.RedactJSON([]byte(nested), Marker{}); err != nil || strings.Contains(string(out), "12345678") {
		t.Errorf("nested numeric password: %s, %v", out, err)
	}
}

type recorder struct {
	mu       sync.Mutex
	findings []Finding
}

func (r *recorder) Replace(f Finding) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, f)
	return fmt.Sprintf("<%s #%d>", f.Kind, len(r.findings))
}

func TestReplacerReceivesFindings(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{})
	rec := &recorder{}
	text := e.RedactString("password: hunter22 and "+fake("ghp_", 36), rec)
	if text != "password: <password #1> and <github_token #2>" {
		t.Fatalf("text = %q", text)
	}
	want := []Finding{{Kind: "password", Value: "hunter22"}, {Kind: "github_token", Value: fake("ghp_", 36)}}
	if !slices.Equal(rec.findings, want) {
		t.Fatalf("findings = %+v, want %+v", rec.findings, want)
	}
}

func TestReplacerValueIsDecoded(t *testing.T) {
	t.Parallel()

	rec := &recorder{}
	_ = newEngine(t, Options{}).RedactString(`prefix {"token": "a\"b\\c-12345"} suffix`, rec)
	if len(rec.findings) != 1 || rec.findings[0].Value != `a"b\c-12345` {
		t.Fatalf("findings = %+v", rec.findings)
	}
}

func TestFindSpansCutTheOriginalText(t *testing.T) {
	t.Parallel()

	text := `ok\npassword: hunter22 ` + fake("ghp_", 36)
	spans := newEngine(t, Options{}).Find(text)
	if len(spans) != 2 {
		t.Fatalf("spans = %+v", spans)
	}
	for _, s := range spans {
		if got := text[s.Start:s.End]; got != s.Finding.Value {
			t.Errorf("span %d:%d cuts %q, finding value %q", s.Start, s.End, got, s.Finding.Value)
		}
	}
	if spans[0].Finding.Value != "hunter22" || spans[1].Finding.Kind != "github_token" {
		t.Errorf("spans = %+v", spans)
	}
	if spans := newEngine(t, Options{}).Find(""); spans != nil {
		t.Errorf("Find(\"\") = %+v", spans)
	}
}

func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	e := newEngine(t, Options{Russian: true, HighEntropy: true})
	text := `{"password":"hunter22","text":"token: ` + fake("", 30) + ` пароль: Qwerty-123"}`
	want := e.RedactString(text, Marker{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				if got := e.RedactString(text, Marker{}); got != want {
					t.Errorf("concurrent result %q, want %q", got, want)
					return
				}
			}
		})
	}
	wg.Wait()
}
