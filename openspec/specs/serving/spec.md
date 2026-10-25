# serving Specification

## Purpose

`mcp-gate serve` puts the downstream servers of a config behind one HTTP listener. Each enabled server is served at `/<name>/mcp` over stateless streamable HTTP, behind named bearer tokens, with its catalog mirrored from the one supervised downstream session and filtered by the server's policy. Calls are forwarded to that session with progress, cancellation and `_meta` handled per call, and their results are redacted, failing closed. The gate reports liveness, readiness and status, and writes one audit line per call.

## Requirements

### Requirement: serve

`mcp-gate serve [-state-dir DIR] <config.yaml>` SHALL load the config as `check` does and exit with status 2, printing every problem, when it is invalid. Otherwise it SHALL make itself non-dumpable and a child subreaper, start a supervisor for every enabled server, listen on `listen.addr`, and log JSON lines to stderr at `logLevel` and above. On SIGINT or SIGTERM it SHALL stop accepting connections, give calls in flight up to 10 seconds, stop every server in parallel, and exit with status 0; it SHALL exit with status 2 when it cannot listen or the listener fails.

#### Scenario: Invalid config

- **WHEN** `serve` is given a config whose server accepts no token
- **THEN** it exits with status 2, naming `servers.<name>.auth`

### Requirement: Routes

Each enabled server SHALL be served at exactly `/<name>/mcp`; any other path, including the route of a disabled server, SHALL get 404. A route SHALL run, in this order: the Host check, the token check, cross-origin protection, a 503 with `Retry-After: 5` while the server's catalog has never been listed, a request body limit of 4 MiB (413) read within 30 seconds (408), and the SDK's stateless streamable HTTP handler, which answers GET with 405. When `listen.allowedHosts` is set, a request whose Host is not in it (an entry without a port matching any port, without regard to case) SHALL get 403. Unless `listen.behindProxy` is set, the SDK's DNS-rebinding check SHALL reject a request to a loopback listener whose Host is not a loopback name. A handler panic SHALL be answered with 500 and logged without its value. The listener SHALL bound request headers to 64 KiB read within 10 seconds and close idle connections after 120 seconds, and SHALL NOT bound the time a call takes.

#### Scenario: Server not connected yet

- **WHEN** a client with a valid token posts to the route of a server that has not connected
- **THEN** it gets 503 with `Retry-After: 5`, and without a token it gets 401

#### Scenario: Paths

- **WHEN** `/s/mcp/`, `/s/`, `/s` or the route of a disabled server is requested
- **THEN** the answer is 404

#### Scenario: Host behind a proxy

- **WHEN** `behindProxy` is set, `allowedHosts` is `[mcp.example.com]`, and requests arrive with Host `MCP.example.com:443` and `other.example.com`
- **THEN** the first is served and the second gets 403

### Requirement: Tokens

A route SHALL accept the tokens in `auth.tokens` unless the server sets `auth.inherit: false`, plus the server's own `auth.tokens`; a server with `auth.public: true` SHALL need no token. A token SHALL be accepted as `Bearer <token>`, with the scheme in any letter case, or as the bare header value; any other request SHALL get 401 with the body `Unauthorized`. Tokens SHALL be compared as SHA-256 digests in constant time, against every token of the route. The name of the matching token SHALL identify the caller in the audit log.

#### Scenario: Named tokens

- **WHEN** a server takes the global token `laptop`, a second server only its own token `phone`, and a third is public
- **THEN** `laptop` reaches only the first, `phone` only the second, the third needs none, and the audit lines name `laptop`, `phone` and no principal

### Requirement: Filters

`tools`, `prompts` and `resources` SHALL each be an allow list or a deny list. Tools and prompts SHALL be matched by name; resources by URI or name, and resource templates by URI template or name. An entry SHALL pass an allow list when any of its keys is listed and fail a deny list when any of its keys is listed. A tool allow list that is empty SHALL filter nothing; an empty prompt or resource allow list SHALL expose none, and the capability SHALL NOT be advertised. A call of a tool or a get of a prompt that is filtered out SHALL fail. Under a resource deny list, a read SHALL be refused when its URI, after normalization (fragment dropped, scheme and host lower-cased, percent-encoded unreserved characters decoded until stable, other escapes upper-cased), is a listed entry or the URI of a resource the list hides, so that a template cannot reach a hidden resource.

#### Scenario: Allow lists

- **WHEN** a server allows the tools `echo` and `sleep`, no prompts, and the resource `fake://info` and the template `items`
- **THEN** it lists those two tools and that resource, does not advertise prompts, refuses a call of another tool and a read of another resource, and reads `fake://items/7` through the template

#### Scenario: Deny list and templates

- **WHEN** a server denies `fake://hidden` and also serves the template `fake://{+path}`
- **THEN** reads of `fake://hidden`, `FAKE://hidden`, `fake://%68idden` and `fake://hidden#x` are refused and `fake://other` is read through the template

### Requirement: Catalog mirror

Each server SHALL be served by one upstream MCP server whose catalog mirrors the downstream one. The gate SHALL list the tools, prompts, resources and resource templates the downstream advertises on every new downstream session, and the kinds it reports changed by list-changed notifications, which for a `2026-07-28` downstream that has not acknowledged its subscription means after every successful probe. A listing that fails SHALL keep the last catalog that was listed and be retried after 2 seconds, doubling up to 1 minute while the session lasts. A restart of the downstream SHALL keep the catalog until the new session has been listed. Entries that did not change SHALL stay registered as they are; a tool whose input schema is not a JSON object of type `object`, and an entry the SDK rejects, SHALL be skipped and logged, keeping its previous version if it had one. Clients that listen for changes SHALL be told when the mirrored lists change.

The upstream server SHALL advertise, independent of the catalog: tools, prompts and resources, each with list-changed notifications, prompts and resources only when the policy can expose some, and no resource subscriptions, logging or other capabilities. It SHALL report the server's name and the gate's version as its implementation.

#### Scenario: Server down

- **WHEN** a mirrored server crashes and waits to restart
- **THEN** clients still list the same tools, and a tool call returns a tool error saying the server is not available (`backoff`); after the restart calls succeed

#### Scenario: List changed

- **WHEN** a downstream tool adds a new tool
- **THEN** the gate lists it, a `2026-07-28` client listening for changes is notified, and the new tool can be called

### Requirement: Forwarding

A call (`tools/call`, `prompts/get`, `resources/read`) SHALL be forwarded on the server's current downstream session, bounded by `callTimeout`, with the upstream request's context, so that the end of the upstream request cancels the downstream call. A `2026-07-28` request is one POST, so a client that gives up cancels its call; for an older client the stateless handler cannot tie a cancellation to the call, which runs until it ends or `callTimeout` ends it. Stopping the gate SHALL cancel the calls in flight.

The downstream request's `_meta` SHALL hold every key of the upstream `_meta` except `progressToken` and keys whose prefix (the part before `/`) has a label `modelcontextprotocol` or `mcp`, which describe the upstream client. When the upstream request has a string or number progress token, the downstream request SHALL carry a token issued by the gate, and the downstream's progress notifications for it SHALL be sent on the upstream request's stream with the client's token and a redacted message. Only the latest progress notification not yet sent SHALL be kept per call, so that a client that does not read its stream holds up only its own call; progress for a call that has ended SHALL be dropped.

Downstream notifications SHALL pass through a queue of 64; when it is full a notification SHALL be dropped and counted. Log messages from the downstream SHALL be logged at debug level, redacted and cut at 4 KiB, and not forwarded.

A call on a server that is not ready SHALL fail at once: a tool call with a tool error naming the state, a prompt get or resource read with an error naming it. A JSON-RPC error from the downstream SHALL keep its code and be redacted; any other error SHALL be described with the server's URL replaced by its config path and redacted, and a deadline as the server not answering in time. A result that asks the client for input (input requests or request state) SHALL NOT be forwarded: the call fails, as a tool error for a tool call.

#### Scenario: Version matrix

- **WHEN** clients offering each of `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25` and `2026-07-28` call a tool through the gate on servers supporting only one of those versions, over stdio and over HTTP
- **THEN** every client negotiates its own version and every call succeeds

#### Scenario: Progress per call

- **WHEN** three clients of different versions call a tool that reports progress, each with its own token, at the same time
- **THEN** each receives progress only for its own call, under its own token

#### Scenario: Meta allow-list

- **WHEN** a `2026-07-28` client calls a tool with `_meta` holding `example.com/trace`, `dev.mcp/x` and a progress token
- **THEN** the downstream request carries `example.com/trace` and a gate progress token, and no reserved key

#### Scenario: Client gives up

- **WHEN** a `2026-07-28` client abandons a call of a tool that never answers
- **THEN** the downstream call is cancelled before `callTimeout`

#### Scenario: Slow reader

- **WHEN** one client stops reading the stream of a call that sends many large progress notifications
- **THEN** another client's call with progress on the same server completes promptly

### Requirement: Redaction

When `redact.enabled` is true, the default, tool results, prompt results, resource read results and JSON-RPC errors from the server SHALL be redacted with the engine built from `redact.ru`, `redact.highEntropy` and `redact.disableRules`, as the redaction spec describes, with a limit of `maxMessageBytes` per text. A result that cannot be redacted SHALL be withheld: the client gets an error saying the result was withheld, never the result. Each finding SHALL be replaced by the text a replacer returns, `[REDACTED:<kind>]` by default. Progress messages and logged texts from the server SHALL be redacted even when results are not.

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

Every forwarded call SHALL be logged as one line with the message `call` and the attributes `server`, `principal` (the token name, empty on a public server), `method`, the tool or prompt name or the resource URI (redacted and cut at 256 bytes), `durMs`, `outcome` (`ok`, `tool_error`, `error`, `denied`, `unavailable`, `withheld` or `input_required`) and `redactions`, the number of findings replaced. Arguments and results SHALL NOT be logged. With `log.requests`, each HTTP request to the server's route SHALL be logged with its method, status, duration and remote address, but not its path, query or headers. Behind a proxy, the remote address SHALL be the right-most `X-Forwarded-For` entry that is not in `listen.trustedProxies`, read only when the peer is in it. The SDK's informational lines, which it writes for every session and so for every stateless request, SHALL be logged at debug level.

#### Scenario: Audit line

- **WHEN** a client holding the token `laptop` calls `echo` and one secret is redacted
- **THEN** the `call` line has `principal` `laptop`, `tool` `echo`, `outcome` `ok` and `redactions` 1

### Requirement: Health

`GET` and `HEAD` of `/_healthz` and `/_readyz` SHALL need no token and answer on any Host; other methods SHALL get 405. GET SHALL return a JSON object with `name` (the config's `name`), `serverCount` (the enabled servers), `status`, `unhealthy` (only when not empty) and `version` (the build's), HEAD only the status code. `/_healthz` SHALL be 200 `ok` while the process serves. `/_readyz` SHALL be 503 `initializing` until every enabled server has had its catalog listed or `startupGracePeriod` has passed since start; then 503 `degraded`, naming them sorted, while any server whose catalog was listed is in a state other than `ready` and `degraded`; 503 `unavailable` when servers are enabled but none was ever listed; and 200 `ok` otherwise.

#### Scenario: Startup and degradation

- **WHEN** a gate with a good server, a failing server and an HTTP server starts with a 1 second grace period, and the HTTP server later goes down and comes back
- **THEN** `/_readyz` is `initializing`, then `ok` after the grace period, then `degraded` naming the HTTP server, then `ok` again, while `/_healthz` is `ok` throughout

#### Scenario: Nothing mounted

- **WHEN** the only server never connects and the grace period has passed
- **THEN** `/_readyz` is 503 `unavailable`

### Requirement: Status

When `admin.tokens` is set, `GET /_status` SHALL return, to a request carrying one of those tokens as on a route, an indented JSON object with the gate's `name`, `version`, whether startup completed (`started`), and per enabled server its state, whether its catalog was listed (`mounted`), protocol version, whether it runs on an automatic pin and the pin it learned, sessions, restarts, the last error (redacted) and its time, the child's PID and resident memory, the last 20 lines of the child's stderr while it is not ready, the counts of tools, prompts, resources and resource templates, the time of the last listing, and the counts of calls, failed calls and dropped notifications. Others SHALL get 401. Without admin tokens the path SHALL be 404. The answer SHALL carry `Cache-Control: no-store`.

#### Scenario: Status

- **WHEN** an admin reads `/_status` while one server is ready and another cannot start
- **THEN** the first shows `ready`, mounted, its tools, PID and protocol version, the second its last error, and a client token gets 401

### Requirement: Learned protocol pins

With a state directory (`-state-dir`, by default the first entry of `$STATE_DIRECTORY`), a protocol pin a supervisor learns SHALL be written to `pins.json` in it, as `{"version": 1, "pins": {"<server>": "<version>"}}`, through a temporary file that is synced and renamed. At start the file SHALL be read and each pin to a version the SDK supports given to its server, which then connects on it without the discover sub-deadline. A missing file SHALL be no pins; a file that cannot be read or parsed SHALL be logged and ignored. Without a state directory, pins SHALL be kept only while the process runs.

#### Scenario: Pin survives a restart

- **WHEN** a server that ignores discover is pinned automatically and the gate is restarted with the same state directory
- **THEN** the server connects on `2025-11-25` at once and is reported as automatically pinned
