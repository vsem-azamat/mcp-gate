# redaction Specification

## Purpose

Redaction finds credentials in the results and errors that downstream MCP servers return and replaces them before they reach a client. It is a library: `internal/redact` is the engine, which works on text and JSON and knows nothing of MCP or HTTP, and `internal/redact/mcpredact` applies it to the MCP results of the official Go SDK. What replaces a finding is decided by a replacer the caller passes in. The scan is pattern based, so a secret without a recognisable shape (a password in plain prose without a label), an encoded secret, or a secret split across messages is not found.

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

Every rule SHALL have its own numeric priority, and rules SHALL run in priority order whatever options are set. When findings of two rules overlap, the finding of the rule with the lower number SHALL win and the other SHALL be dropped. Vendor formats SHALL come before the generic key-value rules, the high-entropy rule after them, and the Russian label rule last. The Russian `логин/пароль` pair rule SHALL come before every other rule, so that no other finding on its line can split it.

#### Scenario: Vendor format inside a key-value pair

- **WHEN** a text contains `token: ` followed by a GitHub token
- **THEN** there is one finding, of kind `github_token`

#### Scenario: Login and password pair

- **WHEN** Russian rules are on and a text contains `логин/пароль: admin / Qwerty123, ключ ` followed by an AWS access key
- **THEN** there is one `password` finding covering the rest of the line

### Requirement: Escaped line breaks

The rules SHALL treat a `\n`, `\r` or `\t` written as a backslash and a letter, as in undecoded JSON or a log line, as a boundary, while `\\n` (an escaped backslash) is not one. The offsets of findings SHALL refer to the original text.

#### Scenario: Token after an escaped newline

- **WHEN** a text contains `Use this token to access the HTTP API:\n` (an escaped newline) directly followed by a Telegram bot token
- **THEN** the token is replaced

### Requirement: JSON

A text that is a JSON object or array SHALL be rewritten value by value: each string value is decoded, redacted and re-encoded, and every other byte (key order, whitespace, numbers) SHALL stay as it was. A value under a member whose name marks a secret SHALL be replaced as a whole. Member names SHALL be compared without case and separators, so `client_secret`, `clientSecret` and `client-secret` are equal; `token` SHALL count only as the whole name or as part of a listed name such as `accessToken`, `refreshToken`, `authToken`, `idToken`, `bearerToken`, `sessionToken` or `apiToken`, and `pin`, `pass` and `pwd` only as the whole name or its last word, so `nextPageToken`, `db_token`, `token_count` and `bypass` do not mark a secret, and names starting with `is` or `has` SHALL NOT mark one. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` SHALL mark an `auth_header` value.

Objects and arrays under a secret member SHALL inherit it: every value below is secret except under members that describe the secret (`type`, `scope`, `expires_in`, `user`, `id` and the like). A number of three or more characters under a secret member SHALL be replaced by the replacement as a JSON string. A string that holds a JSON document SHALL be rewritten the same way, up to five levels deep; below that it is matched as text. A replacer SHALL get the value of a finding inside a JSON string literal decoded.

#### Scenario: Secret member

- **WHEN** a JSON text is `{"client_secret":"abc123def","nextPageToken":"CAESBggB","token_count":5}`
- **THEN** only `abc123def` is replaced

#### Scenario: Layout preserved

- **WHEN** a pretty-printed JSON text has a member `"a": "password: hunter22"` after `"z": 1`
- **THEN** the output differs from the input only in `hunter22`

#### Scenario: Numeric password

- **WHEN** a JSON text is `{"password": 12345678, "count": 12345678}`
- **THEN** the output is `{"password": "[REDACTED:password]", "count": 12345678}`

#### Scenario: Invalid JSON document

- **WHEN** a document passed as JSON is not valid JSON
- **THEN** the engine returns an error and no output

### Requirement: Options

Russian credential labels (`пароль`, `токен`, `ключ`, `секрет`, `код доступа`, with qualifiers such as `от почты`) SHALL be found only with the Russian option. Without an explicit separator, a value after a Russian label SHALL be reported only when it looks like a password. A value that is only Cyrillic words, and after `токен` or `ключ` a technical term such as `ERC-20`, `ED25519`, `12:30` or `50%`, SHALL NOT be reported. The high-entropy rule, which reports tokens of 24 or more base64 characters with mixed case, digits and at least 4 bits of entropy per byte that are not part of a path, URL or SSH public key, SHALL run only with the high-entropy option. Kinds listed as disabled SHALL never be reported, in text or under JSON members; an unknown kind SHALL be an error naming it.

#### Scenario: Russian label

- **WHEN** the Russian option is on and a text contains `пароль от wifi: wifi-Pass-2026`
- **THEN** `wifi-Pass-2026` is replaced

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

The text that replaces each finding SHALL come from a replacer passed with each call. The default replacer SHALL write `[REDACTED:<kind>]`. The engine SHALL hold no mutable state, have no process-wide hooks, and be safe for concurrent use.

#### Scenario: Custom replacer

- **WHEN** a text `password: hunter22 and <GitHub token>` is redacted with a replacer that numbers its findings
- **THEN** the replacer gets `password`/`hunter22` and then `github_token`/the token, and its strings replace them in that order

### Requirement: MCP results

The adapter SHALL redact tool call results, prompt results and resource read results as the SDK decodes them, covering:

- the text of text content, rewritten as JSON when it is a JSON document;
- embedded resources and resource contents: their URI as text, their text, and blobs with a text MIME type (`text/*`, `*+json`, `*+xml`, JSON, XML, YAML, TOML, shell, JavaScript, PEM, form data) that are valid UTF-8; blobs of other types or not valid UTF-8, and image and audio data, SHALL pass unchanged;
- the URI, name, title, description and icon URLs of resource links, as text (icon `data:` URIs pass unchanged);
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

When a result or error cannot be redacted completely, the adapter SHALL return an error and no result, never the original. That covers a value that does not encode or does not decode again, a content kind the adapter does not know, a text, encoded value or error message larger than the configured limit, a blob with a text MIME type larger than 8 MiB, a result that carries input requests or request state (a multi-round-trip result), and a panic anywhere during redaction, including in the replacer. The error SHALL NOT quote the content that failed or the panic value.

#### Scenario: Value that does not encode

- **WHEN** `structuredContent` holds a value that does not encode as JSON
- **THEN** the adapter returns an error and no result

#### Scenario: Panicking replacer

- **WHEN** the replacer panics
- **THEN** the adapter returns an error that does not contain the value it was given

#### Scenario: Large text blob

- **WHEN** a resource holds a `text/plain` blob larger than 8 MiB
- **THEN** the adapter returns an error and no result

#### Scenario: Input requests

- **WHEN** a tool result asks the client for input
- **THEN** the adapter returns an error and no result

#### Scenario: Unknown content kind

- **WHEN** a result holds a content block of a type the adapter does not know
- **THEN** the adapter returns an error and no result
