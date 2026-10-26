# redaction Specification

## Purpose

Redaction finds credentials in the results and errors that downstream MCP servers return and replaces them before they reach a client. It is a library: `internal/redact` is the engine, which works on text and JSON and knows nothing of MCP or HTTP, and `internal/redact/mcpredact` applies it to the MCP results of the official Go SDK. What replaces a finding is decided by a replacer the caller passes in. The scan is pattern based, so a secret without a recognisable shape (a password in plain prose without a label), an encoded secret, or a secret split across messages or content blocks is not found; a vendor token split across two adjacent strings of one JSON document is.

## Requirements

### Requirement: Findings

The engine SHALL report each finding with a kind and the secret value, and for a text also the byte offsets of the value in that text. Findings in one text SHALL be ordered by position and SHALL NOT overlap. The kinds SHALL be `anthropic_api_key`, `auth_header`, `aws_access_key`, `aws_secret_key`, `env_secret`, `github_token`, `gitlab_token`, `google_api_key`, `google_oauth_token`, `high_entropy`, `jwt`, `openai_api_key`, `password`, `private_key`, `secret`, `slack_token`, `slack_webhook`, `stripe_key`, `telegram_bot_token` and `url_password`.

The core rules SHALL find vendor token formats (AWS, GitHub, GitLab, Anthropic, OpenAI, Google, Slack, Telegram bot, Stripe, JWT), PEM private keys (also when the end line is missing), credentials in `Authorization` headers, URL passwords, `.env` and shell assignments whose variable name marks a secret, `key: value` and `key = value` pairs in prose, YAML, INI, code and query strings whose key marks a password, token, secret or API key, command-line flags such as `--password`, and `"key": "value"` fragments in text that is not JSON, including escaped ones. A label split by a zero-width character, a full-width colon or a no-break space SHALL still be found.

#### Scenario: Vendor token

- **WHEN** a text contains a GitHub personal access token
- **THEN** it is replaced and the default replacement is `[REDACTED:github_token]`

#### Scenario: Labelled password

- **WHEN** a text contains `the password: Summer-Blue-77! ok`
- **THEN** `Summer-Blue-77!` is replaced as a `password` finding and the rest of the text is unchanged

#### Scenario: Ordinary text

- **WHEN** a text contains a commit hash, a SHA-256 digest, a UUID, an SSH public key, a pagination token under `nextPageToken`, `TOKEN_URL=https://…`, `PASSWORD_MIN_LENGTH=12`, `PWD=/home/user/project`, `bypass: yes` or `Token: none`
- **THEN** nothing is replaced

### Requirement: Placeholders

A candidate value SHALL NOT be reported when it is shorter than three characters, a word such as `none`, `null`, `true`, `redacted`, `changed` or `valid`, a variable reference (`$TOKEN`, `${DB_PASSWORD}`), a template (`{{…}}`, `%(…)`, `<your-token>`), a mask of one repeated character (`********`, `xxxx`), or contains `[REDACTED`. Trailing sentence punctuation SHALL be dropped from an unquoted value.

#### Scenario: Masked value

- **WHEN** a text contains `password: ********`
- **THEN** nothing is replaced

#### Scenario: Already redacted

- **WHEN** a text that was redacted once is redacted again
- **THEN** the markers it contains are not reported as secrets

### Requirement: Rule priority

Every rule SHALL have its own numeric priority, and rules SHALL run in priority order whatever options are set. Findings that overlap SHALL become one finding covering all of them, so that no part of any of them stays visible; its kind SHALL be that of the finding from the rule with the lowest number, and its value SHALL be the whole covered text, decoded only when the whole merged finding lies inside one JSON string literal. A replacer therefore gets one value that can hold more than one secret, or a secret with text around it: a replacer that keeps values (such as an escrow) keeps the merged value as one. Findings that only touch SHALL stay separate. Vendor formats SHALL come before the generic key-value rules, the high-entropy rule after them, and the Russian label rules last. The Russian `логин/пароль` pair rule SHALL come before every other rule, so that no other finding on its line can split it.

#### Scenario: Vendor format inside a key-value pair

- **WHEN** a text contains `token: ` followed by a GitHub token
- **THEN** there is one finding, of kind `github_token`

#### Scenario: Password running into a token

- **WHEN** a text contains `password: hunter22,` directly followed by a GitHub token
- **THEN** `hunter22,` and the token are replaced together by one `github_token` finding, and `hunter22` does not survive

#### Scenario: One value with several secrets

- **WHEN** a text contains `password: ` followed by a GitHub token, a comma and an AWS access key
- **THEN** a replacer gets one `aws_access_key` finding (the AWS rule has the lowest number) whose value is the token, the comma and the key

#### Scenario: Login and password pair

- **WHEN** Russian rules are on and a text contains `логин/пароль: admin / Qwerty123, ключ ` followed by an AWS access key
- **THEN** there is one `password` finding covering the rest of the line

### Requirement: Escaped line breaks

The rules SHALL treat a `\n`, `\r` or `\t` written as a backslash and a letter, as in undecoded JSON or a log line, as a boundary, while `\\n` (an escaped backslash) is not one. An unquoted value of a key-value pair, a `.env` assignment or a command-line flag SHALL go on over an escaped `\t` and over a NUL byte, and SHALL end at an escaped `\n` or `\r` only when the part before it, measured as it would be replaced (trailing punctuation and surrounding space removed), has at least 8 characters and is no placeholder: a credential on its own. A shorter part runs over the break, since it may be the start of a value that holds one, so the value is replaced whole and nothing replaced before is let through; only the text after an escaped break that follows such an 8-character part is no longer replaced. Escaped line breaks and tabs that a value starts with SHALL be dropped from it when what is left is no placeholder, so a value on a following line is replaced without the breaks. The Russian label rules still run over an escaped line break. The offsets of findings SHALL refer to the original text.

#### Scenario: Token after an escaped newline

- **WHEN** a text contains `Use this token to access the HTTP API:\n` (an escaped newline) directly followed by a Telegram bot token
- **THEN** the token is replaced

#### Scenario: Unquoted value before an escaped newline

- **WHEN** a text is `password: hunter22\nnext line words`, with an escaped newline
- **THEN** the output is `password: [REDACTED:password]\nnext line words`

#### Scenario: Short value before an escaped newline

- **WHEN** a text is `password: abc\ndef`, with an escaped newline
- **THEN** the output is `password: [REDACTED:password]`

#### Scenario: Unquoted value after an escaped newline

- **WHEN** a text is `password:\nhunter22`, with an escaped newline
- **THEN** the output is `password:\n[REDACTED:password]`

### Requirement: Value on the next line

A key of a key-value pair at the end of a line, with its separator (`password:`, `api_key =`, `TOKEN=`, `token =>`, `TOKEN：`) followed only by spaces, tabs, no-break spaces, escaped tabs or zero-width spaces, SHALL take the next line as its value when, after one real line break (`\n` or `\r\n`), that line holds the value alone. Alone means, after leading spaces, tabs or no-break spaces, one quoted value or one unquoted run that holds no whitespace and none of `"'<>&` and does not end with a colon, followed by at most one comma or semicolon and spaces. The value SHALL then be judged as on the key's own line (key classification, placeholders, trailing punctuation, escaped line breaks). Since a JSON string is decoded before it is scanned, this covers a `\n` escape inside a JSON string value. The key SHALL lie within 512 bytes before its separator and the value line SHALL have at most 8192 bytes; longer ones are not matched.

An unquoted next line SHALL NOT be taken when it is the structure of the text rather than a value: a secret key of its own whose value is on the line after it (`API_KEY=`, `TOKEN：`), and found there; a configuration assignment: an upper-case name of at least two characters (`DEBUG=True`, `DB_HOST=`, `TZ=Europe/Prague`) or a lower-case name with `_` (`db_host=`), whatever follows `=`, or another lower-case name with nothing after `=` or a rest that does not mix upper and lower case (`debug=`, `log=info`), so a password such as `Kj8=xP2qLm` or `Hunter=22x`, or base64 padding, is still a value; a control statement of code, with or without a trailing `;` or `,` (`return`, `pass`, `continue`, `break`, `yield`, `raise`, `else` and the like); a URL (it contains `://`); or a Markdown code fence (it starts with three backticks or tildes). A line with more than one word is not a value alone: so `username: alice` (two words) is not taken, nor are prose, headings such as `# Title`, list items such as `- item`, YAML mappings such as `child: x` or a value with a trailing `# comment`; a key alone such as `child:` ends with a colon; a mask such as `---` is a placeholder. Only one line break is crossed: a value after a blank line is not found. No next line SHALL be taken after a key line of code that opens a block: one whose first word after its indentation is `if`, `elif`, `while`, `for`, `with`, `case`, `match`, `except`, `def`, `class` or `switch`, followed up to the key only by an optional `not` (`if not token:` followed by `    sys.exit(1)`, `case 'token':` followed by `    break;`), or by more words of which one before the key is `and`, `or`, `not`, `in` or `is` or holds one of `()[]=!<>&|` (`while retries and token:`, `if len(x) > 0 or token:`). A header word in prose does not open a block, so `for the staging db password:` followed by `hunter22` is found. A next line that is rejected is still scanned by every rule as any other text. Not found: a value after a trailing comment on the key line, YAML block scalars (`password: |`) and multi-line plain scalars, a YAML list item (`- hunter22`), and a value that ends with a colon. A single word after a label is taken as a value as it would be on the label's own line, so `Password:` followed by `Submit` or `TBD` is replaced.

#### Scenario: Value alone on the next line

- **WHEN** a text is `password:` and, on the next line after a real line break, `hunter22`
- **THEN** `hunter22` is replaced as a `password` finding and the line break is kept

#### Scenario: Key on the next line

- **WHEN** a text is `password:` followed on the next line by `username: alice`, or by the YAML lines `  child: x` and `  other: y`
- **THEN** nothing is replaced

#### Scenario: Prose on the next line

- **WHEN** a text is `## Password:` followed on the next line by `Use the reset link below.`
- **THEN** nothing is replaced

### Requirement: JSON

A text that is a JSON object or array SHALL be rewritten value by value: each string value is decoded, redacted and re-encoded, and every other byte (key order, whitespace, numbers) SHALL stay as it was. A value under a member whose name marks a secret SHALL be replaced as a whole. Member names SHALL be scanned by the rules as string values outside a secret member are, and a name holding a finding SHALL be replaced by its redacted form, with `#2`, `#3` and so on appended when that text is already a name of the object, written or given to another replaced name, so that every member stays distinct. Once the search for written names has read eight times the document's size plus 1 MiB (each JSON document nested in a string having a budget of its own) (deeply nested objects with replaced names), replaced names SHALL be kept apart only from the other replacements for the rest of the document, which is otherwise redacted as usual; only there can a replaced name equal a written one. Whether a name marks a secret SHALL be decided on the name as written. Member names SHALL be compared without case and separators, so `client_secret`, `clientSecret` and `client-secret` are equal; `token` SHALL count only as the whole name or as part of a listed name such as `accessToken`, `refreshToken`, `authToken`, `idToken`, `bearerToken`, `sessionToken` or `apiToken`, and `pin`, `pass` and `pwd` only as the whole name or its last word, so `nextPageToken`, `db_token`, `token_count` and `bypass` do not mark a secret, and names starting with `is` or `has` SHALL NOT mark one. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` SHALL mark an `auth_header` value.

Objects and arrays under a secret member SHALL inherit it: every value below is secret except under members that describe the secret (`type`, `scope`, `expires_in`, `user`, `id` and the like). A member name below a secret member SHALL be replaced as a whole, with the secret member's kind, when it looks like a value rather than an identifier: when it is none of the names that describe the secret, no placeholder, and no plain identifier (lower-case, snake or kebab case such as `expires_in` and `token-type`, camel or Pascal case such as `tokenType`, `TokenType` and `userID`, or upper snake case such as `TOKEN_TYPE`), and either it holds a digit or any other character that is not a letter, or it has 12 or more characters and at least 3.5 bits of Shannon entropy per byte, or its value is only a flag: `true`, `false`, `null`, a number, `{}`, `[]` or `""`. So `{"password":{"hunter2":true}}` loses `hunter2`, while a plain identifier such as `hunter` or `enabled` stays whatever its value. A replaced name gets the `#n` suffixes as above, so the document keeps its structure. A number of three or more characters under a secret member SHALL be replaced by the replacement as a JSON string. A string that holds a JSON document SHALL be rewritten the same way, up to five levels deep; below that it is matched as text. A replacer SHALL get the value of a finding inside a JSON string literal decoded.

#### Scenario: Secret member

- **WHEN** a JSON text is `{"client_secret":"abc123def","nextPageToken":"CAESBggB","token_count":5}`
- **THEN** only `abc123def` is replaced

#### Scenario: Layout preserved

- **WHEN** a pretty-printed JSON text has a member `"a": "password: hunter22"` after `"z": 1`
- **THEN** the output differs from the input only in `hunter22`

#### Scenario: Secret as a member name

- **WHEN** a JSON text is `{"scopes":{"<GitHub token A>":"repo","<GitHub token B>":"admin"}}`
- **THEN** the output is `{"scopes":{"[REDACTED:github_token]":"repo","[REDACTED:github_token]#2":"admin"}}`

#### Scenario: Name under a secret member

- **WHEN** a JSON text is `{"password":{"hunter2":true,"hunter3":false,"type":"x","enabled":true}}`
- **THEN** the output is `{"password":{"[REDACTED:password]":true,"[REDACTED:password]#2":false,"type":"x","enabled":true}}`

#### Scenario: Numeric password

- **WHEN** a JSON text is `{"password": 12345678, "count": 12345678}`
- **THEN** the output is `{"password": "[REDACTED:password]", "count": 12345678}`

#### Scenario: Invalid JSON document

- **WHEN** a document passed as JSON is not valid JSON
- **THEN** the engine returns an error and no output

### Requirement: Tokens split across JSON strings

The vendor-format rules (AWS access keys, GitHub, GitLab, Anthropic, OpenAI, Google, Slack tokens and webhooks, Telegram bot, Stripe, JWT), and no other rule, SHALL also find a token that starts in one string of a JSON document and ends in the adjacent one. Strings are adjacent when they are consecutive elements of an array, the values of consecutive members of an object, or a member name and its value, with only JSON space and the separators between them; the strings of JSON nested in a string are matched in that document. A boundary SHALL be matched only when the first string ends and the second starts with a token character (a letter, a digit, or one of `_-./:`), over a window that joins the run of token characters that ends the first string, at most its last 256 bytes, to the run that starts the second, at most its first 256 bytes; it SHALL be scanned only when it holds, in any letter case, the start of a vendor format (as the rules' prefilters list them) or a digit followed by a colon. Only a match that starts in the first string and ends in the second SHALL count, and not when a vendor rule finds a whole token that ends the first string, so `{"<GitHub token>":"repo"}` keeps `repo`. A match that reaches the start or end of a window cut short SHALL run on over the rest of that run of token characters.

The part of the token in the first string SHALL be replaced by what the replacer returns for one finding of the rule's kind whose value is the whole token, both parts joined; the part in the second string SHALL be replaced by the fixed `[REDACTED:continued]`, for which the replacer is not called. A finding of the strings' own scan that overlaps a part SHALL be cut back to what lies outside it. When the first string is a value under a secret member, it SHALL be replaced as a whole, with the member's kind and a value that holds the string and the rest of the token; when the second one is, `[REDACTED:continued]` SHALL be followed by the replacement of what follows the token. A replacer that keeps values (such as an escrow) therefore keeps a split token once, whole, under the first part. Not found: a token split over three or more strings (only the part in the first two is found), a start of the token more than 256 bytes before the end of the first string, and splits across content blocks or messages.

#### Scenario: Token split across array elements

- **WHEN** a JSON text is `["use ghp_abcd", "<rest of the GitHub token> now"]`
- **THEN** the output is `["use [REDACTED:github_token]", "[REDACTED:continued] now"]`, and the replacer gets one finding whose value is the whole token

#### Scenario: Whole token as a member name

- **WHEN** a JSON text is `{"<GitHub token>":"repo"}`
- **THEN** only the name is replaced

#### Scenario: Key and value in two strings

- **WHEN** a JSON text is `["password:", "hunter22"]`
- **THEN** nothing is replaced

### Requirement: Options

Russian credential labels (`пароль`, `токен`, `ключ`, `секрет`, `код доступа`, with qualifiers such as `от почты`) SHALL be found only with the Russian option. Without an explicit separator, a value after a Russian label SHALL be reported only when it looks like a password. A label with an explicit separator at the end of a line (`Пароль:`) SHALL take as its value the start of the next line, after one real line break, unless that value is an unquoted run that is the key of a pair on its line: it holds no escaped line break, ends with `:`, `=` or `：` or is followed by spaces and one of them, and more text follows on the line (`username: alice`, `токен: X`). Such a next line SHALL still be scanned by every rule, so a label on it is matched with its own value. A value that is only Cyrillic words, and after `токен` or `ключ` a technical term such as `ERC-20`, `ED25519`, `12:30` or `50%`, SHALL NOT be reported. The high-entropy rule, which reports tokens of 24 or more base64 characters with mixed case, digits and at least 4 bits of entropy per byte that are not part of a path, URL or SSH public key, SHALL run only with the high-entropy option. Kinds listed as disabled SHALL never be reported, in text or under JSON members; an unknown kind SHALL be an error naming it.

#### Scenario: Russian label

- **WHEN** the Russian option is on and a text contains `пароль от wifi: wifi-Pass-2026`
- **THEN** `wifi-Pass-2026` is replaced

#### Scenario: Russian label before a label

- **WHEN** the Russian option is on and a text is `пароль:` followed on the next line by `токен: Abc12345xyz`, or by `username: alice`
- **THEN** `Abc12345xyz` is replaced, and `username: alice` is left as it is

#### Scenario: Russian prose

- **WHEN** the Russian option is on and a text contains `токен: истёк` or `ключ от квартиры у соседа`
- **THEN** nothing is replaced

#### Scenario: Russian option off

- **WHEN** the Russian option is off and a text contains `Пароль: Summer-Blue-77!`
- **THEN** nothing is replaced

#### Scenario: Disabled kind

- **WHEN** `jwt` and `password` are disabled and a text contains a JWT and `password: hunter22`
- **THEN** nothing is replaced

#### Scenario: Unknown kind

- **WHEN** a disabled kind is not one of the kinds
- **THEN** the engine is not created and the error names the kind

### Requirement: Replacer

The text that replaces each finding SHALL come from a replacer passed with each call, except for the second part of a token split across JSON strings, which SHALL always be `[REDACTED:continued]`. The default replacer SHALL write `[REDACTED:<kind>]`. The engine SHALL hold no mutable state, have no process-wide hooks, and be safe for concurrent use.

#### Scenario: Custom replacer

- **WHEN** a text `password: hunter22 and <GitHub token>` is redacted with a replacer that numbers its findings
- **THEN** the replacer gets `password`/`hunter22` and then `github_token`/the token, and its strings replace them in that order

### Requirement: MCP results

The adapter SHALL redact tool call results, prompt results and resource read results as the SDK decodes them, covering:

- the text of text content, rewritten as JSON when it is a JSON document;
- embedded resources and resource contents: their URI as text, their text, and text blobs: blobs with a text MIME type (`text/*`, `*+json`, `*+xml`, JSON, XML, YAML, TOML, shell, JavaScript, PEM, form data), and blobs without a MIME type or with `application/octet-stream` that are valid UTF-8 without a NUL byte; other blobs, and image and audio data, SHALL pass unchanged;
- the URI, name, title, description and icon URLs of resource links, as text (icon `data:image/` URIs pass unchanged);
- tool-use input and tool-result content, its nested content and structured content;
- `structuredContent` and every `_meta` (of the result, of each content block, of resource contents), rewritten as JSON;
- the description (as text) and the messages of a prompt result.

The adapter SHALL NOT modify its input; a part with nothing to redact MAY be shared between input and output.

#### Scenario: Every text field

- **WHEN** a tool result holds the same token in text content, an embedded resource, a text blob, a resource link, tool-use input, nested tool-result content, `structuredContent` and `_meta`
- **THEN** the encoded redacted result contains the token only in image and audio data

#### Scenario: Number in structured content

- **WHEN** `structuredContent` is `{"pin": 123456}`
- **THEN** the redacted `structuredContent` is `{"pin": "[REDACTED:password]"}`

### Requirement: Errors

The adapter SHALL redact the message of a downstream error and, for a JSON-RPC error in it, that error's message and data; data that is not valid JSON SHALL be dropped. An error without findings SHALL be returned unchanged. A redacted JSON-RPC error SHALL keep its code. A redacted error SHALL still match the `errors.Is` targets of the original (such as a cancelled context), SHALL NOT unwrap to the original, and `errors.As` SHALL find only a redacted JSON-RPC error in it.

#### Scenario: Token in an error

- **WHEN** a downstream error is `bad credentials for <GitHub token>: context deadline exceeded`
- **THEN** the message has the token replaced and the error still matches `context.DeadlineExceeded`

### Requirement: Failing closed

When a result or error cannot be redacted completely, the adapter SHALL return an error and no result, never the original. That covers a value that does not encode or does not decode again, a content kind the adapter does not know, a text, encoded value or error message larger than the configured limit, a text blob that is larger than 8 MiB, or one with a text MIME type that is not valid UTF-8, a result that carries non-empty input requests or request state (a multi-round-trip result), and a panic anywhere during redaction, including in the replacer. The error SHALL NOT quote the content that failed or the panic value.

#### Scenario: Value that does not encode

- **WHEN** `structuredContent` holds a value that does not encode as JSON
- **THEN** the adapter returns an error and no result

#### Scenario: Panicking replacer

- **WHEN** the replacer panics
- **THEN** the adapter returns an error that does not contain the value it was given

#### Scenario: Unscannable text blob

- **WHEN** a resource holds a `text/plain` blob larger than 8 MiB, or one that is not valid UTF-8
- **THEN** the adapter returns an error and no result

#### Scenario: Input requests

- **WHEN** a tool result asks the client for input
- **THEN** the adapter returns an error and no result

#### Scenario: Unknown content kind

- **WHEN** a result holds a content block of a type the adapter does not know
- **THEN** the adapter returns an error and no result
