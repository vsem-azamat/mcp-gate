# escrow Specification

## Purpose

The escrow keeps the secrets that redaction replaces, in memory, under random handles, so that the owner can release a secret through an authenticated HTTP API without its value ever entering a client's context. Its HTTP API is a frozen contract: paths, methods, the authentication scheme, the response fields, status codes and bodies are those of the mcp-proxy escrow it replaces, so that its consumers work unchanged. The one addition is a limit on failed authentication per client address.

## Requirements

### Requirement: Enabling

The escrow SHALL be on exactly when a key hash, the hex SHA-256 of the API key (64 hex digits in either letter case, surrounding space ignored), comes from one of these sources, in order of precedence: the config's `escrow.keyHash`; the file named by the config's `escrow.keyHashFile`; the environment variable `MCP_GATE_ESCROW_KEY_SHA256`; and `MCP_HUB_ESCROW_KEY_SHA256`, its deprecated name. A variable that holds only space SHALL count as unset. The key itself SHALL never reach the gate. Every source that is set SHALL hold a hex SHA-256, and all of them SHALL hold the same one; otherwise `serve` SHALL exit with status 2, naming the sources but no value. When `MCP_HUB_ESCROW_KEY_SHA256` is set, `serve` SHALL log one warning at start that it is deprecated. Both variables, and every variable that `escrow.keyHash` is expanded from, SHALL be removed from the environment stdio servers inherit from. With the escrow off, results SHALL carry `[REDACTED:<kind>]` markers and `/_escrow/` SHALL be 404 like any unknown path.

`escrow.keyHashFile` SHALL be read once at start, following symlinks; it SHALL be a regular file of at most 1 KiB, writable by neither its group nor others, and owned by root or by the gate's user (by anyone when the gate runs as root), and its content, with surrounding space removed, SHALL be the hex SHA-256. A file that fails these checks SHALL make `serve` exit with status 2, without quoting its path or content.

#### Scenario: Escrow off

- **WHEN** the gate runs with no key hash in the config or the environment
- **THEN** a tool result with a password carries `[REDACTED:password]`, and `GET /_escrow/kaaaaaaaaaa/meta` with any key is 404 `404 page not found`

#### Scenario: Deprecated variable

- **WHEN** only `MCP_HUB_ESCROW_KEY_SHA256` holds the key hash
- **THEN** the escrow is on and serves the API exactly as with `MCP_GATE_ESCROW_KEY_SHA256`, and the gate logs one warning at start

#### Scenario: Conflicting key hashes

- **WHEN** `MCP_GATE_ESCROW_KEY_SHA256` and `MCP_HUB_ESCROW_KEY_SHA256`, or `escrow.keyHash` and a variable, hold different hashes
- **THEN** `serve` exits with status 2 naming both sources, and `check` fails the same way

#### Scenario: Key hash file

- **WHEN** `escrow.keyHashFile` names a file mode 0400 that holds the hash and a line break
- **THEN** the escrow is on with that hash; when the file is writable by its group, `serve` exits with status 2

### Requirement: Per-server escrow

A server SHALL use the escrow only when its `redact.escrow` is true, the default. With `redact.escrow: false`, its findings SHALL get `[REDACTED:<kind>]` and SHALL NOT be kept, and its files with secrets SHALL be withheld with `[REDACTED:file]` and SHALL NOT be kept, as with the escrow off.

#### Scenario: Server opted out

- **WHEN** the escrow is on and a server with `redact.escrow: false` returns a password
- **THEN** the client gets `[REDACTED:password]` and no entry is kept

### Requirement: Markers

With the escrow on, each finding in a result or a JSON-RPC error of a server with redaction and `redact.escrow` SHALL be kept and replaced by `[REDACTED:<kind> #<handle>]`, where the handle is `k` followed by ten characters of lower-case RFC 4648 base32 from a cryptographic random source. A finding whose value is over 64 KiB, or one the store cannot take, SHALL be replaced by `[REDACTED:<kind>]` and not kept. The same value from the same server under the same kind SHALL get the handle it already has while that entry lives, and seeing it again SHALL extend the entry to a full TTL from then. Texts outside results (progress messages, logged texts) SHALL get `[REDACTED:<kind>]` and SHALL NOT be kept.

#### Scenario: Marker in a result

- **WHEN** a tool returns `the password: Summer-Blue-77! ok`
- **THEN** the client gets `the password: [REDACTED:password #<handle>] ok`, and the API returns `Summer-Blue-77!` for the handle

#### Scenario: Same secret twice

- **WHEN** one result holds the same password twice
- **THEN** both markers carry the same handle

### Requirement: Store

Entries SHALL live only in the process's memory, never on disk or in a log. Each SHALL record its kind (or `file`), server, tool (the tool or prompt name, or the resource URI), creation and expiry times, and a summary of the request's arguments that keeps only the members named in `escrow.sourceArguments` (by default `chat_id`, `message_id`, `message_ids`, `topic_id`, `reply_to`, `space`, `space_name`, `message_name`, `thread_name`, `attachment_name`, `conversation_id`, `conversationId`, `channel_id`, `chat`, `peer`, `messageId`, `threadId` and `account`; an empty list keeps none), when they are strings of at most 200 bytes without line breaks, numbers, booleans, or lists of at most 20 strings and numbers. An entry SHALL expire after its server's `redact.escrowTTL` (by default `escrow.ttl`, by default `24h`); expired entries SHALL be unreadable and SHALL be dropped every minute. The store SHALL hold at most `escrow.maxEntries` entries (default 1000) and 16 MiB of values: a new entry SHALL first drop expired entries when the store is full, then evict the oldest entries until it fits. A value SHALL be overwritten in memory when its entry is dropped.

#### Scenario: Configured source arguments

- **WHEN** `escrow.sourceArguments` is `[ticket]` and a call with `ticket: T-1` and `chat_id: 42` returns a secret
- **THEN** the entry's meta has `source` `{"ticket":"T-1"}`

#### Scenario: Expiry

- **WHEN** an entry's TTL has passed
- **THEN** its meta and value are 404

#### Scenario: Eviction

- **WHEN** the store is full and a new secret is kept
- **THEN** the oldest entry is no longer readable

### Requirement: Authentication

The API SHALL be served at `/_escrow/` on the main listener, outside the MCP routes, so that neither their Host check nor their tokens nor their filters apply, unless `escrow.tcp` is `false`: then `/_escrow/` on the listener SHALL be 404 like any unknown path, and the API SHALL be served only on the escrow socket. Except as the socket requirement allows, every request SHALL carry `Authorization: Bearer <key>`, the scheme in any letter case; the key, with surrounding space removed, SHALL be hashed with SHA-256 and compared with the configured hash in constant time. A request without the key, including a client or admin token and the bare key without a scheme, SHALL get 401 with `WWW-Authenticate: Bearer realm="escrow"` and the body `Unauthorized`, whatever its path or method.

#### Scenario: Wrong key

- **WHEN** a request carries no key, `Bearer nope`, the key with a character added, the bare key, or a client token
- **THEN** it gets 401 for the meta and value of a live handle and of an unknown handle alike

### Requirement: Socket

With `escrow.socket` set and the escrow on, the gate SHALL also serve the API, with the same paths, answers and logs, on a unix socket at `escrow.socket.path`, and nothing else there (any other path is 404). At start it SHALL create the socket's parent directory with mode 0700 when it is missing; remove a socket file already at the path when nothing accepts connections on it; refuse to start (status 2) when the path holds anything other than a socket, or a socket another process listens on; and set the socket file's mode to `escrow.socket.mode` (default 0600). At shutdown it SHALL remove the socket file. With the escrow off, no socket SHALL be opened, and a warning SHALL say so.

On the socket, the client SHALL be the peer's user ID as the kernel reports it when the peer connected (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS), written `unix:uid=<n>` in the access log and keying the failed-authentication limit. A request from a user ID in `escrow.socket.allowUIDs` (by default only the gate's own user; an empty list allows none) SHALL be served without a key and SHALL NOT spend from the limit. A request from any other user ID, or one whose user ID cannot be read (`unix:uid=unknown`), SHALL need the key exactly as on the listener: it is not refused for its user ID alone. Requests on the listener SHALL never be served without the key.

#### Scenario: Own user without a key

- **WHEN** the gate's own user requests a live handle's value on the socket without an `Authorization` header
- **THEN** it gets 200 with the value, and the access log names `unix:uid=<its uid>`

#### Scenario: Other user

- **WHEN** `allowUIDs` does not hold the peer's user ID
- **THEN** a request without the key gets 401, and one with the key is served

#### Scenario: Socket only

- **WHEN** `escrow.tcp` is `false`
- **THEN** `/_escrow/` on the listener is 404 with the key, and the socket serves the API

#### Scenario: Stale socket

- **WHEN** a socket file left by a process that exited is at the path
- **THEN** the gate replaces it; a regular file at the path stops the start and is left untouched

### Requirement: Failed-authentication limit

Each client SHALL have a budget of 20 attempts, of which a request presenting a wrong key (`Bearer` with a non-empty key) SHALL spend one, and which SHALL earn one back every 3 seconds up to 20. A request presenting no key, or another scheme, SHALL get 401 without spending any, since it cannot be a guess. A client with less than one attempt left SHALL get 429 with `Retry-After` (in whole seconds) and the body `Too Many Requests` for every request, even one with the right key. The client SHALL be the peer address unless `listen.behindProxy` is set and the peer is in `listen.trustedProxies`; then it SHALL be the right-most `X-Forwarded-For` entry that is not in `listen.trustedProxies`. IPv6 addresses SHALL count by their /64. At most 4096 clients SHALL be tracked; a new one SHALL then replace the client with the most attempts left, so that a client that never presented a wrong key is never refused. Trusting a proxy on loopback trusts every local process to name its own client address.

#### Scenario: Behind a proxy

- **WHEN** `behindProxy` is set and 20 requests from the proxy with `X-Forwarded-For: 203.0.113.5` present a wrong key
- **THEN** a request with the right key and the same `X-Forwarded-For` gets 429, and one with `X-Forwarded-For: 203.0.113.6` is served

#### Scenario: Requests without a key

- **WHEN** a client sends any number of requests without an `Authorization` header
- **THEN** each gets 401, and a following request with the right key is served

#### Scenario: Not behind a proxy

- **WHEN** `behindProxy` is not set and the same requests arrive
- **THEN** `X-Forwarded-For` is ignored and the second client gets 429 too, since both come from the same peer

### Requirement: API

With the key, the API SHALL answer:

- `GET` and `HEAD` of `/_escrow/<handle>/meta`: 200 with `Content-Type: application/json` and one line of JSON, an object with the members `handle`, `type` (the finding's kind, or `file`), `kind` (`text` or `file`), `server`, `tool`, `source` (the argument summary, `{}` when empty), `created_at` and `expires_at` (RFC 3339 UTC, whole seconds) and `preview` in this order, and for a file also `file_name` and `size`; HEAD with the headers only. The preview of a text value SHALL be its first 4 and last 3 characters around `…` when it has 12 or more characters, its first 2 and last 1 when it has 8 to 11, and `…` otherwise or when it is not UTF-8; a file's preview SHALL be empty. Meta SHALL never hold the value or a file's path.
- `GET /_escrow/<handle>`: 200 with `Content-Type: application/octet-stream`, `Content-Length` and the value; for a file, its bytes, only while it is a regular file at its place under its root, reached without a symlink, with the size and SHA-256 it had when it was scanned, and 404 otherwise.
- `DELETE /_escrow/<handle>`: 204 with no body; the entry is gone.

A path whose handle does not have the handle form, or that has a part after the handle other than `meta`, and a handle that is unknown, expired or deleted SHALL get 404 with the body `Not Found`. Any other method on a valid path SHALL get 405 with the body `Method Not Allowed`. Every answer of the API SHALL carry `Cache-Control: no-store`. Error bodies SHALL be plain text with a trailing newline, as Go's `http.Error` writes them. A panic SHALL be answered with 500 `Internal Server Error`.

#### Scenario: Contract

- **WHEN** a secret is kept and its meta, value and deletion are requested with the key
- **THEN** meta has the members in order with the type, server, tool, source summary and preview, the value is returned as `application/octet-stream`, deletion is 204, and afterwards the meta, the value and a second deletion are 404

#### Scenario: Methods and paths

- **WHEN** `POST` or `PUT` of a value path, `DELETE` or `POST` of a meta path, or `HEAD` of a value path is requested with the key
- **THEN** each is 405; `GET` of `/_escrow/not-a-handle`, `/_escrow/<handle>/other` and `/_escrow/` is 404

### Requirement: Logs

Each API request SHALL be logged with the operation (`meta`, `value` or `delete`), the handle (or `<invalid>` when it does not have the handle form), the status and the client address, but never the key or a value. Keeping a secret SHALL be logged with its handle, kind and server; keeping a file with its handle, server, tool, the kinds found and its size.

#### Scenario: No value in the logs

- **WHEN** a secret is kept and released
- **THEN** no log line holds the secret, the key or an argument outside the summary
