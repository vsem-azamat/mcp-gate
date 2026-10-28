# argument-secrets Specification

## Purpose

Redaction keeps secrets out of what servers return; this capability covers what clients send. The gate scans the arguments of each request for secrets before it forwards them, and logs or refuses a request that would send one to a server. A secret the gate holds in the escrow can still reach a server on purpose: an agent passes the escrow handle it was shown, and the gate puts the value in, where the server's config allows that handle, so that the model never sees the secret. Both decide which secret may go where, so they are specified together.

## Requirements

### Requirement: Argument scan

Each request to a server whose results are redacted SHALL be scanned before it is forwarded, with the server's redaction engine (its rules, `redact.ru`, `redact.highEntropy` and `redact.disableRules`): the arguments of a tool call as the JSON document they are, the arguments of a prompt get as a JSON object of their names and values, and the URI of a resource read as text, so that a secret member name (such as `password` or `api_key`) marks its value as it does in a result. `redact.arguments` SHALL decide what a finding does: `off` scans nothing; `log`, the default, forwards the request and records the kinds found; `block` refuses the request and records them. A refused tool call SHALL be answered with a tool error, a prompt get or resource read with an error; either SHALL name the kinds found and never a value, and say that a secret is passed as an escrow handle. Escrow markers (`[REDACTED:<kind>]`, `[REDACTED:<kind> #<handle>]`) SHALL NOT be findings, so the handles that substitution replaces are never reported, while a secret the client wrote out is. On a server with `redact.enabled: false` nothing SHALL be scanned, and `redact.arguments: block` there SHALL be a config error. The scan catches secrets sent by mistake, not by a client that means to hide them: text that holds `[REDACTED` is never a finding, and an encoded or split secret is not recognised. Not scanned: tool and prompt names, the request's `_meta`.

#### Scenario: Secret in a tool call, block

- **WHEN** a server has `redact.arguments: block` and a client calls `send_message` with `{"text": "the key is <GitHub token>"}`
- **THEN** the call is not forwarded, the client gets a tool error naming `github_token` and not the token, and the audit line has outcome `refused` and `argumentSecrets` `github_token`

#### Scenario: Secret in a tool call, log

- **WHEN** a server has the default `redact.arguments` and a client calls a tool with `{"password": "hunter22"}`
- **THEN** the call is forwarded unchanged and the audit line has outcome `ok` and `argumentSecrets` `password`

#### Scenario: Prompt and resource

- **WHEN** a server has `redact.arguments: block` and a client gets a prompt with the argument `token` set to a GitHub token, or reads `db://x?password=hunter22`
- **THEN** each is refused with an error naming the kind, and the server sees neither

#### Scenario: Handle in the arguments

- **WHEN** a server has `redact.arguments: block` and a client passes `[REDACTED:password #<handle>]` in an argument
- **THEN** the scan finds nothing

### Requirement: Substitution rules

A server's `redact.substitute` SHALL list where escrow handles in its tool calls are replaced by their values; it is empty by default, and substitution is then off. Each rule SHALL name a `tool` (the server's own name for it), an `argument` and `from`, a map from the name of a server, the handle's origin, to the kinds of finding from it that may go there. `argument` SHALL be a path of member names separated by `.` from the top of the arguments to a string value, in which `*` SHALL match any member name or any array element and a number SHALL match the array element of that index; a member name that holds `.` or is `*` cannot be named. A rule SHALL need `redact.enabled` on its server, an existing server and at least one redaction kind, each listed once, under each `from` entry, and no two rules of a server SHALL have the same tool and argument; a `from` server whose results carry no handles (`redact.enabled: false` or `redact.escrow: false`) SHALL be warned about. A server MAY name itself in `from`. Substitution applies to tool calls only.

#### Scenario: Rule validation

- **WHEN** a rule names a server that does not exist in `from`, a kind that is not a redaction kind, or the same tool and argument as another rule
- **THEN** `check` fails naming the field

### Requirement: Substitution

In a tool call, every string value at a path a rule of the tool matches SHALL have each escrow marker `[REDACTED:<kind> #<handle>]` in it replaced by its handle's value, and each `[REDACTED:continued]` removed, as the escrow spec restores a text, before the call is forwarded. A marker SHALL be replaced only when all of these hold: the escrow is on and holds a live text entry under the handle; the marker's kind is the entry's; the entry was shown to the caller's token, that is, a result the token received carried the handle (see Recipients in the escrow spec); and one of the rules that match the path lists the entry's server under `from`, with the entry's kind. Otherwise the call SHALL be refused, with a tool error that names the argument as the rule writes it, the handle and whether it is unknown (also when it is expired, a file, of another kind, or not shown to the token) or not allowed there, and outcome `refused`, and no value SHALL be forwarded. Markers in a value no rule matches SHALL be forwarded as text, as on a server without rules. A rule binds a value to an argument, not to a destination: the server decides where the value goes, from every other argument too (a `fetch` tool's `url`, a `send` tool's recipient), so a rule SHALL be written only for a tool whose destination the arguments cannot choose. A substituted value is part of the arguments the server receives, so a protocol version that copies arguments into request headers (`Mcp-Param-*` for header-bound parameters) sends it there too. A call with substitutions SHALL be forwarded with its arguments encoded again; one without, unchanged.

#### Scenario: Substituted password

- **WHEN** a result of the server `vault` gave the token `laptop` the marker `[REDACTED:password #<handle>]`, the server `app` has the rule `{tool: login, argument: password, from: {vault: [password]}}`, and `laptop` calls `login` with `{"user": "alice", "password": "[REDACTED:password #<handle>]"}`
- **THEN** `app` receives the password in `password`, `user` unchanged, and the audit line lists the substitution

#### Scenario: Handle from another server

- **WHEN** the same marker came from `mail`, which the rule does not list, and `laptop` passes it in `password`
- **THEN** the call is refused, `app` receives nothing, and the error names the argument and the handle as not allowed there

#### Scenario: Handle another token was shown

- **WHEN** only `laptop` received the marker and `phone` passes it in `password`
- **THEN** the call is refused as with an unknown handle

#### Scenario: Handle outside the rules

- **WHEN** `laptop` passes the marker in `user`, which no rule covers
- **THEN** `app` receives the marker as text

### Requirement: Echoed values

A server that receives substituted values may return them. The answer of a call with substitutions SHALL still be redacted, and each substituted value SHALL be a finding wherever redaction scans the result or a JSON-RPC error (see MCP results in the redaction spec), as written or as a JSON string escapes it, whatever its shape, and in the call's progress messages. A finding that is exactly a substituted value SHALL be replaced by the marker the client passed, with its handle, and SHALL NOT be kept in the escrow again, so that a value never gains the target server as its origin; a finding that holds a substituted value with more text SHALL be replaced by `[REDACTED:<kind>]` and not kept. A value is found as written, as a JSON string escapes it, percent-encoded as a query value or a path segment, and in base64 (standard or URL alphabet) when its encoding starts on a group of the surrounding base64. A value transformed otherwise (another case, reversed, split across fields or texts, another encoding) reaches the client. The server's log messages, the files it writes and data redaction does not scan (images, audio, binary blobs, numbers) are scanned by the rules only, if at all. In later calls the value is found only by the rules, and then gets the handle it was substituted from (see Recipients in the escrow spec).

#### Scenario: Echo

- **WHEN** `login` of the scenario above answers `welcome alice, your password is <the password>`
- **THEN** the client gets `welcome alice, your password is [REDACTED:password #<handle>]` with the same handle, and the escrow holds no new entry

### Requirement: Audit

The `call` line SHALL carry `argumentSecrets`, the kinds the scan found, sorted and joined by `,`, when it found any, and `substitutions`, one `<handle>:<kind>:<origin>:<argument>` per replaced marker with the argument as its rule writes it, when there were any. Neither SHALL hold a value or an argument name the rule does not write. A request refused by the scan or by substitution SHALL have outcome `refused` and no `substitutions`, since it sends nothing, even when some of its markers were valid, and a refused substitution SHALL also be logged as a warning with the server, the tool, the argument as its rule writes it, the handle and the reason.

#### Scenario: Audit of a substitution

- **WHEN** the substitution of the password scenario succeeds
- **THEN** the `call` line has `substitutions` `<handle>:password:vault:password`, and no line holds the password
