# serving Specification

## Purpose

Each enabled server's catalog is mirrored from its one supervised downstream session and filtered by the server's policy (and, per token, by the token's policy; see the token-policies spec). Calls are forwarded to that session with progress, cancellation and `_meta` handled per call, and their results are redacted, failing closed, with the files of download tools scanned (see the file-scanning spec) and the secrets kept in the escrow when it is on (see the escrow spec). The gate writes one audit line per call. How the gate runs, its routes and tokens, the aggregate endpoint and reloads are in the gate-lifecycle, routes-and-auth, aggregate-endpoint and reload specs.

## Requirements

### Requirement: Filters

`tools`, `prompts` and `resources` SHALL each be an allow list or a deny list. Tools and prompts SHALL be matched by name; resources by URI or name, and resource templates by URI template or name. An entry SHALL pass an allow list when any of its keys is listed and fail a deny list when any of its keys is listed. A tool allow list that is empty SHALL filter nothing; an empty prompt or resource allow list SHALL expose none, and the capability SHALL NOT be advertised. A call of a tool or a get of a prompt that is filtered out SHALL fail. Under a resource deny list, a read SHALL be refused when the comparison key of its URI is the key of a listed entry or of the URI of a resource the list hides, so that a template does not reach a hidden resource by another spelling, and when a template the list hides matches the URI, since the server may serve it through that template. The key SHALL decode every percent-encoding until none is left, drop the query and the fragment, lower-case the scheme and the authority, drop user information, a port and a trailing dot from the authority and a `localhost` authority, and take the authority and path as one path in which `;` parameters, surrounding spaces and NULs, and empty and `.` segments are dropped and `..` segments resolved, so that the number of slashes after the scheme does not matter. It SHALL then remove invisible characters from the key (format characters such as a zero-width space or a byte order mark, control characters, variation selectors and the other default ignorable code points), trim surrounding Unicode spaces from each segment of its path, clean the path again, and drop a trailing dot from its first segment and that segment when it is `localhost`, so that `fake://hid%E2%80%8Bden` has the key of `fake://hidden`; this step SHALL depend only on the key before it, so that URIs that shared a key still share one. A deny list matches spellings, not what a server makes of them, so it is a best effort; an allow list is the boundary. Under an allow list, a read SHALL reach only an allowed resource or a resource through an allowed template, and SHALL be refused when the comparison key of its URI is that of the URI of a listed resource the list does not allow: whatever its query when that URI has none, and, when it has one, when the read's query, together with the `;` parameters of the read's path, holds each of its parameters. Parameters SHALL be compared decoded, split at `&` and `;` and at the first `=`, with `+` as a space, the same invisible characters as in the key removed (format and control characters before a key's `[...]` suffix is found, the others after), keys and values trimmed of spaces and `=` and lower-cased, a `[...]` suffix dropped from a key, a value that reads as a number once every `_` and space in it is dropped (decimal or with a `0x`, `0o` or `0b` prefix, with a sign, a fraction and an exponent, and at most 128 characters long without its padding zeros, or else all digits) compared by its finite value at 256-bit precision, empty parameters ignored and repetition counting as presence; a hidden parameter without a value SHALL be held by its key with any value. So hiding `db://t?id=1` refuses `db://t?ID=01&x=y`, `db://t;id=1`, `db://t?id[]=1`, `db://t?id=1.0`, `db://t?id=0x1` and `db://t?id==1`, but not `db://t?id=2`, `db://t?id=10` or `db://t`, and hiding `db://t?flag` refuses `db://t?flag=1`; a template may still match URIs of resources the server does not list. One algorithm SHALL decide reads under a server's resource filter and under a token's.

#### Scenario: Allow lists

- **WHEN** a server allows the tools `echo` and `sleep`, no prompts, and the resource `fake://info` and the template `items`
- **THEN** it lists those two tools and that resource, does not advertise prompts, refuses a call of another tool with a `denied` audit line and a read of another resource, and reads `fake://items/7` through the template

#### Scenario: Deny list and templates

- **WHEN** a server denies `fake://hidden` and also serves the template `fake://{+path}`
- **THEN** reads of `fake://hidden`, `FAKE://hidden`, `fake://%68idden`, `fake://hidden#x`, `fake://hidden/`, `fake://hidden?`, `fake:///hidden` and `fake://x/../hidden` are refused and `fake://other` is read through the template

#### Scenario: Hidden template and hidden spelling

- **WHEN** a server denies the template `items` (`fake://items/{id}`) and also serves `fake://{+path}`, and another allows only `fake://{+path}` and `fake://info` while listing `fake://hidden`
- **THEN** the first refuses `fake://items/7` and reads `fake://other`; the second reads `fake://other` and `fake://info` and refuses `fake://hidden` and `FAKE://%68idden`

#### Scenario: Invisible characters in the path under an allow list

- **WHEN** a server allows only `fake://{+path}` and `fake://info` while listing `fake://hidden`
- **THEN** it refuses `fake://hid%E2%80%8Bden` and `fake://hidden%EF%BB%BF`, and reads `fake://caf%C3%A9`

#### Scenario: Hidden URI with a query under an allow list

- **WHEN** a server allows only the template `db://{+path}` while listing `db://t?id=1` and `db://f?flag`
- **THEN** it refuses `db://t?id=1`, `db://t;id=1`, `db://t?id[]=1`, `db://t?id=1.0`, `db://t?id=0x1`, `db://t?id==1`, `db://t?id=%E2%80%8B1` and `db://f?flag=1`, and reads `db://t?id=2`, `db://t?id=10`, `db://t?id=12`, `db://t`, `db://t?x=1` and `db://f`

### Requirement: Catalog mirror

Each server SHALL be served by one upstream MCP server whose catalog mirrors the downstream one, and by one more for each token with a policy on it (see the token-policies spec). The gate SHALL list the tools, prompts, resources and resource templates the downstream advertises on every new downstream session, and the kinds it reports changed by list-changed notifications, which for a `2026-07-28` downstream that has not acknowledged its subscription means after every successful probe. A server that answers the resource template listing with "method not found" SHALL be taken to have no templates. A listing of one kind SHALL fail when it takes more than 1000 pages, or holds more than 50000 entries or more than 64 MiB of entries encoded as JSON. A listing that fails SHALL keep the last catalog that was listed and be retried after 2 seconds, doubling up to 1 minute while the session lasts. A restart of the downstream SHALL keep the catalog until the new session has been listed. Entries that did not change SHALL stay registered as they are; a tool whose input schema is not a JSON object of type `object`, and an entry the SDK rejects, SHALL be skipped and logged, keeping its previous version if it had one. Clients that listen for changes SHALL be told when the mirrored lists change.

The upstream server SHALL advertise, independent of the catalog: tools, prompts and resources, each with list-changed notifications, prompts and resources only when the policy can expose some, and no resource subscriptions, logging or other capabilities. It SHALL report the server's name and the gate's version as its implementation.

#### Scenario: Server down

- **WHEN** a mirrored server crashes and waits to restart
- **THEN** clients still list the same tools, and a tool call returns a tool error saying the server is not available (`backoff`); after the restart calls succeed

#### Scenario: List changed

- **WHEN** a downstream tool adds a new tool
- **THEN** the gate lists it, a `2026-07-28` client listening for changes is notified, and the new tool can be called

### Requirement: Forwarding

A call (`tools/call`, `prompts/get`, `resources/read`) SHALL be forwarded on the server's current downstream session, bounded by `callTimeout`, with the upstream request's context, so that the end of the upstream request cancels the downstream call. A `2026-07-28` request is one POST, so a client that gives up cancels its call; for an older client the stateless handler cannot tie a cancellation to the call, which runs until it ends or `callTimeout` ends it. Stopping the gate SHALL cancel the calls in flight.

The upstream `_meta` describes the client and the downstream servers are third parties, so the downstream request's `_meta` SHALL hold only the upstream keys listed, by exact name, in the server's `forwardMeta` (none by default), besides the gate's progress token. When the upstream request has a string or number progress token, the downstream request SHALL carry a token issued by the gate, and the downstream's progress notifications for it SHALL be sent on the upstream request's stream with the client's token and a redacted message. Only the latest progress notification not yet sent SHALL be kept per call, so that a client that does not read its stream holds up only its own call; progress for a call that has ended SHALL be dropped.

Downstream notifications SHALL pass through a queue of 64; when it is full a notification SHALL be dropped and counted. Log messages from the downstream SHALL be logged at debug level, redacted and cut at 4 KiB, and not forwarded.

A call on a server that is not ready SHALL fail at once: a tool call with a tool error naming the state, a prompt get or resource read with an error naming it. Every error from the downstream SHALL be rebuilt before it reaches the client, with the server's URL replaced by its config path in its message, and a deadline described as the server not answering in time. A JSON-RPC error, including the one the SDK reports when an HTTP request cannot be sent, SHALL keep its code; with results redacted its message and the data of an error reply SHALL be redacted as results are, the data with the URL replaced too, and otherwise its message SHALL be redacted and cut as any other error's and its data dropped. Any other error SHALL be described by its message with the URL replaced, redacted and cut at 512 bytes. No cut SHALL split a UTF-8 character. A result that asks the client for input (input requests or request state) SHALL NOT be forwarded: the call fails, as a tool error for a tool call.

#### Scenario: Transport failure on an HTTP server

- **WHEN** an HTTP server whose URL holds a credential in its path stops accepting connections and a client calls a tool, with results redacted or not
- **THEN** the error the client gets names `<servers.NAME.http.url>` and not the URL

#### Scenario: Version matrix

- **WHEN** clients offering each of `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25` and `2026-07-28` call a tool through the gate on servers supporting only one of those versions, over stdio and over HTTP
- **THEN** every client negotiates its own version and every call succeeds

#### Scenario: Progress per call

- **WHEN** three clients of different versions call a tool that reports progress, each with its own token, at the same time
- **THEN** each receives progress only for its own call, under its own token

#### Scenario: Listed meta key passes, unlisted key is dropped

- **WHEN** a `2026-07-28` client calls a tool with `_meta` holding `example.com/trace`, `example.com/session`, `dev.mcp/x` and a progress token, on a server with `forwardMeta: [example.com/trace]` and on one without `forwardMeta`
- **THEN** the first server's request carries `example.com/trace` and a gate progress token, the second's only a gate progress token, and the unlisted keys reach neither

#### Scenario: Client gives up

- **WHEN** a `2026-07-28` client abandons a call of a tool that never answers
- **THEN** the downstream call is cancelled before `callTimeout`

#### Scenario: Slow reader

- **WHEN** one client stops reading the stream of a call that sends many large progress notifications
- **THEN** another client's call with progress on the same server completes promptly

#### Scenario: Client that stops reading

- **WHEN** a client sends a call and never reads its answer, which is larger than the connection buffers
- **THEN** within about 30 seconds of the write stalling the connection is closed and the call is cancelled

### Requirement: Redaction

When `redact.enabled` is true, the default, tool results, prompt results, resource read results and JSON-RPC errors from the server SHALL be redacted with the engine built from `redact.ru`, `redact.highEntropy` and `redact.disableRules`, as the redaction spec describes, with a limit of `maxMessageBytes` per text. A result that cannot be redacted SHALL be withheld: the client gets an error saying the result was withheld, never the result. Each finding SHALL be replaced by `[REDACTED:<kind>]`, or, with the escrow on and `redact.escrow` true, by the escrow's marker for the call it came from. A tool result of a file tool SHALL then go through file scanning, and a file that cannot be scanned SHALL withhold the result the same way. Progress messages and logged texts from the server, including the logger name of a log message and the keys and errors of catalog entries the SDK rejects, SHALL be redacted even when results are not, always with `[REDACTED:<kind>]`.

#### Scenario: Token in a result

- **WHEN** a tool returns a GitHub token on a server with redaction on
- **THEN** the client gets `[REDACTED:github_token]`, the audit line counts one redaction, and the token is in no log line

#### Scenario: Redaction off

- **WHEN** the same tool runs on a server with `redact.enabled: false`
- **THEN** the client gets the token

#### Scenario: Result that cannot be redacted

- **WHEN** a tool returns an embedded `text/plain` blob that is not valid UTF-8
- **THEN** the call fails with an error saying the result was withheld, and the audit outcome is `withheld`

### Requirement: Audit and request logs

Every forwarded call, and every tool call or prompt get the SDK refuses before it is forwarded (with outcome `denied` when the name is not in the mirrored catalog, such as a tool the policy hides, or the token's policy hides it, and `error` otherwise), SHALL be logged as one line with the message `call` and the attributes `server`, `principal` (the token name, empty on a public server), `method`, the tool or prompt name or the resource URI (redacted and cut at 256 bytes), `durMs`, `outcome` (`ok`, `tool_error`, `error`, `denied`, `unavailable`, `withheld` or `input_required`), `tokenPolicy` (what the token's policy on the server decided: `none` without one, `allow` or `deny`; a call the token's policy hides has outcome `denied`) and `redactions`, the number of findings replaced and files withheld. Arguments and results SHALL NOT be logged. With `log.requests`, each HTTP request to the server's route SHALL be logged with its method, status, duration and remote address, but not its path, query or headers. A request that a reload hands on to the current config (see the reload spec) SHALL be logged by each route it reached, the first line with `handedOn: true`. Behind a proxy, the remote address SHALL be the right-most `X-Forwarded-For` entry that is not in `listen.trustedProxies`, read only when the peer is in it. The SDK's informational lines, which it writes for every session and so for every stateless request, SHALL be logged at debug level.

#### Scenario: Audit line

- **WHEN** a client holding the token `laptop` calls `echo` and one secret is redacted
- **THEN** the `call` line has `principal` `laptop`, `tool` `echo`, `outcome` `ok`, `tokenPolicy` `none` and `redactions` 1
