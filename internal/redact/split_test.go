package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNamesUnderSecretMembers(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, in, want string }{
		{
			name: "a name with a digit",
			in:   `{"password":{"hunter2":true}}`,
			want: `{"password":{"[REDACTED:password]":true}}`,
		},
		{
			name: "names replaced alike stay apart",
			in:   `{"password":{"hunter2":true,"hunter3":false,"other":null}}`,
			want: `{"password":{"[REDACTED:password]":true,"[REDACTED:password]#2":false,"other":null}}`,
		},
		{
			name: "a name that is not an identifier, whatever its value",
			in:   `{"secret":{"correct horse":"value","api2":{"key":"value"}}}`,
			want: `{"secret":{"[REDACTED:secret]":"[REDACTED:secret]","[REDACTED:secret]#2":{"key":"[REDACTED:secret]"}}}`,
		},
		{
			name: "a name that is not a plain identifier, with a flag as its value",
			in:   `{"password":{"Пароль":1, "hUnTeR":{}, "qWeRtY":"", "plain":[]}}`,
			want: `{"password":{"[REDACTED:password]":1, "[REDACTED:password]#2":{}, "[REDACTED:password]#3":"", "plain":[]}}`,
		},
		{
			name: "a random name of letters",
			in:   `{"token":{"xQzWvKpLmNbRtY":"value"}}`,
			want: `{"token":{"[REDACTED:secret]":"[REDACTED:secret]"}}`,
		},
		{
			name: "plain identifiers and names that describe the secret stay",
			in:   `{"credentials":{"enabled":true,"tokenType":{},"TOKEN_TYPE":null,"token-type":"","TokenType":false,"expires_in":3600,"type":"Bearer","userID":7}}`,
			want: `{"credentials":{"enabled":true,"tokenType":{},"TOKEN_TYPE":null,"token-type":"","TokenType":false,"expires_in":3600,"type":"Bearer","userID":7}}`,
		},
		{
			name: "identifiers with digits stay, a word with digits does not",
			in:   `{"credentials":{"oauth2":{},"auth_provider_x509_cert_url":"","sha256Hash":null,"oauth2Token":0,"apiV2":[],"hunter2":true,"pass1234":false,"MyPassword1":true,"LetMeIn2024":true,"Summer2024Sale":true,"hunter2_x":true}}`,
			want: `{"credentials":{"oauth2":{},"auth_provider_x509_cert_url":"","sha256Hash":null,"oauth2Token":0,"apiV2":[],"[REDACTED:secret]":true,"[REDACTED:secret]#2":false,"[REDACTED:secret]#3":true,"[REDACTED:secret]#4":true,"[REDACTED:secret]#5":true,"[REDACTED:secret]#6":true}}`,
		},
		{
			name: "in an array under a secret member",
			in:   `{"password":[{"hunter2":true}]}`,
			want: `{"password":[{"[REDACTED:password]":true}]}`,
		},
		{
			name: "not under a member that describes the secret",
			in:   `{"token":{"scope":{"read9":true}}}`,
			want: `{"token":{"scope":{"read9":true}}}`,
		},
		{
			name: "not outside a secret member",
			in:   `{"flags":{"hunter2":true}}`,
			want: `{"flags":{"hunter2":true}}`,
		},
		{
			name: "a written name is avoided",
			in:   `{"password":{"[REDACTED:password]":true,"hunter2":true}}`,
			want: `{"password":{"[REDACTED:password]":true,"[REDACTED:password]#2":true}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, opts := range optionSets {
				got, err := newEngine(t, opts).RedactJSON([]byte(tc.in), Marker{})
				if err != nil || string(got) != tc.want {
					t.Fatalf("%+v: RedactJSON = %s, %v; want %s", opts, got, err, tc.want)
				}
			}
		})
	}
	if got := newEngine(t, Options{DisableRules: []string{kindPassword}}).RedactString(`{"password":{"hunter2":true}}`, Marker{}); got != `{"password":{"hunter2":true}}` {
		t.Errorf("a disabled kind replaced a name: %s", got)
	}
}

func TestTokensSplitAcrossStrings(t *testing.T) {
	t.Parallel()

	gh := fake("ghp_", 36)
	jwt := "eyJ" + fake("", 20) + ".eyJ" + fake("", 30) + "." + fake("", 43)
	aws := fake("AKIA", 0) + "IOSFODNN7EXAMPLE"
	bot := "7123456789:" + fake("AA", 33)
	long := fake("", 400)
	oa := fake("sk-proj-", 120)
	longJWT := "eyJ" + fake("", 40) + ".eyJ" + fake("", 700) + "." + fake("", 300)
	const cont = ContinuationMarker
	for _, tc := range []struct{ name, in, want string }{
		{
			name: "array elements",
			in:   `["` + gh[:10] + `", "` + gh[10:] + `"]`,
			want: `["[REDACTED:github_token]", "` + cont + `"]`,
		},
		{
			name: "text around the parts",
			in:   `["see ` + gh[:6] + `","` + gh[6:] + ` now"]`,
			want: `["see [REDACTED:github_token]","` + cont + ` now"]`,
		},
		{
			name: "consecutive member values",
			in:   `{"a":"` + jwt[:40] + `","b":"` + jwt[40:] + `"}`,
			want: `{"a":"[REDACTED:jwt]","b":"` + cont + `"}`,
		},
		{
			name: "a name and its value",
			in:   `{"` + aws[:8] + `":"` + aws[8:] + `"}`,
			want: `{"[REDACTED:aws_access_key]":"` + cont + `"}`,
		},
		{
			name: "split at the colon of a bot token",
			in:   `["bot ` + bot[:10] + `","` + bot[10:] + `"]`,
			want: `["bot [REDACTED:telegram_bot_token]","` + cont + `"]`,
		},
		{
			name: "the second part under a secret member",
			in:   `{"a":"` + gh[:10] + `","password":"` + gh[10:] + ` rest"}`,
			want: `{"a":"[REDACTED:github_token]","password":"[REDACTED:password]"}`,
		},
		{
			name: "the first part under a secret member",
			in:   `{"password":"pw ` + gh[:10] + `","b":"` + gh[10:] + `"}`,
			want: `{"password":"[REDACTED:password]","b":"` + cont + `"}`,
		},
		{
			name: "a second part longer than the window",
			in:   `["` + gh[:10] + `","` + gh[10:] + long + ` tail"]`,
			want: `["[REDACTED:github_token]","` + cont + ` tail"]`,
		},
		{
			name: "a first part that matches on its own",
			in:   `["` + oa[:48] + `","` + oa[48:] + `"]`,
			want: `["[REDACTED:openai_api_key]","` + cont + `"]`,
		},
		{
			name: "a whole token followed by a word, between values",
			in:   `{"a":"` + gh + `","b":"repo","c":["` + fake("xoxb-", 30) + `","general"]}`,
			want: `{"a":"[REDACTED:github_token]","b":"repo","c":["[REDACTED:slack_token]","general"]}`,
		},
		{
			name: "a value continues one token only",
			in:   `{"a":"x ` + gh[:10] + `","` + gh[:6] + `":"` + gh[10:] + `"}`,
			want: `{"a":"x [REDACTED:github_token]","` + gh[:6] + `":"` + cont + `"}`,
		},
		{
			name: "a whole token as a name",
			in:   `{"` + gh + `":"repo"}`,
			want: `{"[REDACTED:github_token]":"repo"}`,
		},
		{
			name: "space at the boundary",
			in:   `["` + gh[:10] + ` ","` + gh[10:] + `"]`,
			want: `["` + gh[:10] + ` ","` + gh[10:] + `"]`,
		},
		{
			name: "strings that are not adjacent",
			in:   `[["` + gh[:10] + `"],"` + gh[10:] + `"]`,
			want: `[["` + gh[:10] + `"],"` + gh[10:] + `"]`,
		},
		{
			name: "a long JWT split after its first 256 bytes",
			in:   `["Bearer ` + longJWT[:600] + `","` + longJWT[600:] + `"]`,
			want: `["Bearer [REDACTED:jwt]","` + cont + `"]`,
		},
		{
			name: "ordinary strings",
			in:   `{"sender":"user 1","date":"2026-10-14T10:00:00Z","list":["a1","b2"]}`,
			want: `{"sender":"user 1","date":"2026-10-14T10:00:00Z","list":["a1","b2"]}`,
		},
		{
			name: "no key-value rule across strings",
			in:   `["` + pw + `:","hunter22"]`,
			want: `["` + pw + `:","hunter22"]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, opts := range []Options{{}, {Russian: true}} {
				got, err := newEngine(t, opts).RedactJSON([]byte(tc.in), Marker{})
				if err != nil || string(got) != tc.want {
					t.Fatalf("%+v: RedactJSON = %s, %v; want %s", opts, got, err, tc.want)
				}
			}
		})
	}

	// The replacer gets the whole token once, for the first part.
	rec := &recorder{}
	doc, err := json.Marshal([]string{"x " + gh[:10], gh[10:] + " y"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := newEngine(t, Options{}).RedactJSON(doc, rec)
	if err != nil || len(rec.findings) != 1 || rec.findings[0] != (Finding{Kind: "github_token", Value: gh}) {
		t.Fatalf("findings = %+v, %v", rec.findings, err)
	}
	if want := `["x <github_token #1>","` + cont + ` y"]`; string(out) != want {
		t.Fatalf("RedactJSON = %s, want %s", out, want)
	}
	// A disabled kind is not found across strings either.
	in := `["` + gh[:10] + `","` + gh[10:] + `"]`
	if got := newEngine(t, Options{DisableRules: []string{"github_token"}}).RedactString(in, Marker{}); got != in {
		t.Errorf("a disabled kind was found: %s", got)
	}
	// In text, the strings of a JSON fragment are not joined.
	if got := newEngine(t, Options{}).RedactText(in, Marker{}); strings.Contains(got, cont) {
		t.Errorf("text was joined: %s", got)
	}
}

// A long JWT is found at every cut between two strings, however far its parts reach into
// either string; only a cut in its signature after a whole JWT leaves the rest of the signature,
// since a whole JWT is never joined to the next string.
func TestLongJWTCutAnywhere(t *testing.T) {
	t.Parallel()

	header, payload, signature := "eyJ"+fake("", 60), "eyJ"+fake("", 900), fake("", 316)
	jwt := header + "." + payload + "." + signature
	whole := len(header) + 1 + len(payload) + 1 + 8 // from here on a holds a whole JWT
	e := newEngine(t, Options{})
	for cut := 1; cut < len(jwt); cut++ {
		in := `{"auth":"Bearer ` + jwt[:cut] + `","next":"` + jwt[cut:] + `"}`
		got, err := e.RedactJSON([]byte(in), Marker{})
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Auth, Next string }
		if err := json.Unmarshal(got, &out); err != nil {
			t.Fatal(err)
		}
		if out.Auth != "Bearer [REDACTED:jwt]" {
			t.Fatalf("cut %d: auth = %q", cut, out.Auth)
		}
		if cut < whole && out.Next != ContinuationMarker {
			t.Fatalf("cut %d: next = %q", cut, out.Next)
		}
	}
}
