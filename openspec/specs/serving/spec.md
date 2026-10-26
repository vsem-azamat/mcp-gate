# serving Specification

## Purpose

`mcp-gate serve` puts the downstream servers of a config behind one HTTP listener. Each enabled server is served at `/<name>/mcp` over stateless streamable HTTP, behind named bearer tokens, and optionally many of them together at `/mcp`, with its catalog mirrored from the one supervised downstream session and filtered by the server's policy and, per token, by the token's policy. Calls are forwarded to that session with progress, cancellation and `_meta` handled per call, and their results are redacted, failing closed, with the files of download tools scanned (see the file-scanning spec) and the secrets kept in the escrow when it is on (see the escrow spec). The gate reports liveness, readiness and status, and writes one audit line per call.

## Requirements

### Requirement: serve

`mcp-gate serve [-state-dir DIR] <config.yaml>` SHALL load the config as `check` does and exit with status 2, printing every problem, when it is invalid, and also when the escrow key hash cannot be resolved (see the escrow spec). Otherwise it SHALL make itself non-dumpable and a child subreaper, start a supervisor for every enabled server (OAuth servers with the grants in the `oauth` directory of the state directory, see the oauth spec), listen on `listen.addr`, and log JSON lines to stderr at `logLevel` and above. On SIGINT or SIGTERM it SHALL stop accepting connections, close the connections on which no request has arrived, end the `subscriptions/listen` streams, give calls in flight up to 10 seconds (their progress still delivered), stop every server in parallel, logging one that does not stop within 15 seconds, and exit with status 0; it SHALL exit with status 2 when it cannot listen or the listener fails.

#### Scenario: Shutdown with a listening client

- **WHEN** a `2026-07-28` client listens for changes and another runs a call with progress while the gate gets SIGTERM
- **THEN** the shutdown does not wait for the listening client, and the call completes with its progress

#### Scenario: Shutdown with an unused connection

- **WHEN** a client has opened a connection but sent no request on it when the gate gets SIGTERM
- **THEN** the gate closes that connection and does not wait for it

#### Scenario: Invalid config

- **WHEN** `serve` is given a config whose server accepts no token
- **THEN** it exits with status 2, naming `servers.<name>.auth`

### Requirement: Routes

Each enabled server SHALL be served at exactly `/<name>/mcp`; any other path, including the route of a disabled server, SHALL get 404, except `/mcp` when the aggregate endpoint is on (see Aggregate endpoint), `/_healthz`, `/_readyz`, `/_status` and, with the escrow on and `escrow.tcp` true, the escrow API under `/_escrow/`, which none of the route checks below apply to. A route SHALL run, in this order: the Host check, the token check, cross-origin protection, a 503 with `Retry-After: 5` while the server's catalog has never been listed, a request body limit of 4 MiB (413) read within 30 seconds (408), and the SDK's stateless streamable HTTP handler, which answers GET with 405. A POST holding one JSON-RPC call SHALL be answered with `application/json` when its client accepts `application/json`, it is not `subscriptions/listen`, and its params carry no `_meta.progressToken` unless the client accepts only `application/json`; a batch, a `subscriptions/listen` request and a request with a progress token SHALL be answered with a `text/event-stream`, as SHALL a request whose client accepts `text/event-stream` but not `application/json`. A client that accepts only one of the two types (counting `*/*`, `application/*` and `text/*`, and not a type given `q=0`, which a wildcard does not override) SHALL get that one, a request with a progress token then losing its progress when it is `application/json`; `subscriptions/listen` without `text/event-stream`, and any request accepting neither, SHALL get 400. Notifications and responses from the client SHALL get 202 with no body. When `listen.allowedHosts` is set, a request whose Host is not in it (an entry without a port matching any port, without regard to case) SHALL get 403. Unless `listen.behindProxy` is set, the SDK's DNS-rebinding check SHALL reject a request to a loopback listener whose Host is not a loopback name. A panic in an HTTP handler SHALL be answered with 500, and a panic while handling an MCP request or a notification with an internal JSON-RPC error or nothing; either SHALL be logged by its type, without its value. The listener SHALL bound request headers to 64 KiB read within 10 seconds and close idle connections after 120 seconds, and SHALL NOT bound the time a call takes. Each write of a response, of at most 64 KiB, SHALL fail when it has not completed within 30 seconds; the connection is then closed and the request's context cancelled, which cancels its call, so a client that stops reading cannot hold the gate's resources while the connection stays up. This holds for the escrow API and the socket as well.

#### Scenario: Server not connected yet

- **WHEN** a client with a valid token posts to the route of a server that has not connected
- **THEN** it gets 503 with `Retry-After: 5`, and without a token it gets 401

#### Scenario: Paths

- **WHEN** `/s/mcp/`, `/s/`, `/s` or the route of a disabled server is requested
- **THEN** the answer is 404

#### Scenario: Response types

- **WHEN** a client accepting both types calls a tool without a progress token, then with one, and a client accepting only `text/event-stream` calls it without one
- **THEN** the first gets `application/json` holding the response, the second a `text/event-stream` of its progress notifications followed by the response, and the third a `text/event-stream`; results are redacted and audit lines written alike

#### Scenario: Host behind a proxy

- **WHEN** `behindProxy` is set, `allowedHosts` is `[mcp.example.com]`, and requests arrive with Host `MCP.example.com:443` and `other.example.com`
- **THEN** the first is served and the second gets 403

### Requirement: Tokens

A route SHALL accept the tokens in `auth.tokens` unless the server sets `auth.inherit: false`, plus the server's own `auth.tokens`; a server with `auth.public: true` SHALL need no token. A token SHALL be accepted as `Bearer <token>`, with the scheme in any letter case, or as the bare header value; any other request SHALL get 401 with the body `Unauthorized`. Tokens SHALL be compared as SHA-256 digests in constant time, against every token of the route. The name of the matching token SHALL identify the caller in the audit log.

#### Scenario: Named tokens

- **WHEN** a server takes the global token `laptop`, a second server only its own token `phone`, and a third is public
- **THEN** `laptop` reaches only the first, `phone` only the second, the third needs none, and the audit lines name `laptop`, `phone` and no principal

### Requirement: Aggregate endpoint

With `aggregate` set, the gate SHALL also serve the servers of `aggregate.servers` (every enabled server by default) together at exactly `/mcp`, which no server route can be, through the same chain as a server route with these differences. A request SHALL reach a member exactly when that member's own route would accept its `Authorization` header: a public member always, any other when the token is one the member accepts. A request without the header SHALL reach the public members; a request whose credential no member accepts, or that reaches no member, SHALL get 401 with the body `Unauthorized`, even when there are public members. A request SHALL get 503 with `Retry-After: 5` until startup is over (see Health) or every member it reaches has had its catalog listed or is in `needs-login`.

A request SHALL be served a catalog of only the members it reaches, computed for that set of members and the token's policies on them: each member's tools and prompts as the member's own route lists them to the token, renamed `<server>__<name>`, and its resources and resource templates with their URIs unchanged. A tool or prompt whose new name is longer than 64 characters or holds a character other than ASCII letters, digits, `_`, `.` and `-` SHALL be left out of it and logged once, and a call of it SHALL be refused with a `denied` line naming the member. A resource URI, or a resource template, that more than one of those members lists SHALL be left out of it and logged once, counting entries the token's policy hides. A read SHALL be routed as for a token without a policy, so that a policy changes no read's member. A resource read SHALL go to the one member that lists the URI, or, when none lists it, to the one member with a template that matches it; when no member or more than one qualifies, the read SHALL fail as one of an unknown resource. The upstream server SHALL advertise tools, and prompts and resources when any of the members' does, each with list-changed notifications, and SHALL report the config's `name` and the gate's version as its implementation.

A tool call, prompt get or resource read SHALL be checked again against the access of the request before it is handed to the member, and SHALL then be handled by the member as on its own route: its filters, the token's policy, `forwardMeta`, `callTimeout`, progress, cancellation, redaction, file scanning and escrow, its errors, and its audit line, which SHALL name the member as `server`, the member's own name for the tool or prompt, and as `principal` the name the member gives the token. A request the aggregate refuses before a member sees it, because it names no member the request reaches or is a read that more than one member's templates match, SHALL be logged, with the name redacted under every redaction rule, as a `call` line with outcome `denied`, `tokenPolicy` `none`, an empty `server`, the name as the client sent it, and the request's token names joined by commas as `principal`. A change in a member's catalog SHALL reach the aggregate catalog, and clients that listen for changes there SHALL be told. A member keeps its entries in the aggregate catalog while it is down, as on its own route, and a member whose catalog was never listed has none. `/_readyz` and `/_status` SHALL NOT report the aggregate endpoint. `aggregate.log.requests` SHALL log the requests to `/mcp` as `log.requests` does for a server, naming `/mcp` as the server.

#### Scenario: Tokens with different access

- **WHEN** `alpha` takes the global token `laptop`, `beta` only its own token `phone`, `pub` is public with the tool allow list `[echo]`, and all three are on the aggregate endpoint
- **THEN** `laptop` lists and calls the tools of `alpha` and `pub`, `phone` those of `beta` and `pub`, a request without a token only `pub__echo`; a call of `beta__echo` with `laptop` or of `alpha__echo` with `phone` fails as one of an unknown tool and is logged `denied` with an empty `server`; `pub__sleep` is refused by `pub`'s filter with a `denied` line naming `pub`; and a wrong token gets 401

#### Scenario: Same behaviour as the server's route

- **WHEN** a client calls `alpha__echo` with a GitHub token in the text, `alpha__badblob`, and `alpha__progress` with a progress token, through the aggregate endpoint
- **THEN** the token is replaced by `[REDACTED:github_token]` and the audit line names `alpha` and counts one redaction, the blob result is withheld, and the progress reaches the client

#### Scenario: Catalog change and a long name

- **WHEN** a member adds the tool `fresh` and a tool whose prefixed name is 65 characters long
- **THEN** a `2026-07-28` client listening on `/mcp` is notified, `alpha__fresh` is listed and can be called, and the long tool is listed only on the member's own route

#### Scenario: Resource on two members

- **WHEN** two members both list `fake://info` and the template `fake://items/{id}`
- **THEN** the aggregate catalog lists neither, and reads of `fake://info` and `fake://items/7` fail

### Requirement: Filters

`tools`, `prompts` and `resources` SHALL each be an allow list or a deny list. Tools and prompts SHALL be matched by name; resources by URI or name, and resource templates by URI template or name. An entry SHALL pass an allow list when any of its keys is listed and fail a deny list when any of its keys is listed. A tool allow list that is empty SHALL filter nothing; an empty prompt or resource allow list SHALL expose none, and the capability SHALL NOT be advertised. A call of a tool or a get of a prompt that is filtered out SHALL fail. Under a resource deny list, a read SHALL be refused when the comparison key of its URI is the key of a listed entry or of the URI of a resource the list hides, so that a template does not reach a hidden resource by another spelling. The key SHALL decode every percent-encoding until none is left, drop the query and the fragment, lower-case the scheme and the authority, drop user information, a port and a trailing dot from the authority and a `localhost` authority, and take the authority and path as one path in which `;` parameters, surrounding spaces and NULs, and empty and `.` segments are dropped and `..` segments resolved, so that the number of slashes after the scheme does not matter. A deny list matches spellings, not what a server makes of them, so it is a best effort; an allow list is the boundary. Under an allow list, a read SHALL reach only an allowed resource or a resource through an allowed template, which may also match URIs of resources the list does not allow.

#### Scenario: Allow lists

- **WHEN** a server allows the tools `echo` and `sleep`, no prompts, and the resource `fake://info` and the template `items`
- **THEN** it lists those two tools and that resource, does not advertise prompts, refuses a call of another tool with a `denied` audit line and a read of another resource, and reads `fake://items/7` through the template

#### Scenario: Deny list and templates

- **WHEN** a server denies `fake://hidden` and also serves the template `fake://{+path}`
- **THEN** reads of `fake://hidden`, `FAKE://hidden`, `fake://%68idden`, `fake://hidden#x`, `fake://hidden/`, `fake://hidden?`, `fake:///hidden` and `fake://x/../hidden` are refused and `fake://other` is read through the template

### Requirement: Token policies

A token with a policy on a server (`policies.<token>.servers.<server>`) SHALL see and reach only what both the server's filters and the policy's pass. The policy's filters SHALL be matched as a server's filters of the same kind, except that an empty allow list SHALL expose nothing for tools too; a filter the policy leaves out, and a server it does not name, SHALL narrow nothing. The results of `tools/list`, `prompts/list`, `resources/list` and `resources/templates/list` SHALL leave out what the policy hides and carry the cache scope `private`. A tool call or prompt get of an entry the policy hides SHALL fail with the error of a name the server does not have, and a resource read of a URI the policy does not pass with the error of an unknown resource, so that a token cannot tell a hidden entry from a missing one. A read SHALL pass when the resource the server lists under its URI passes, or, when none is listed, a template that matches it passes; under a deny list it SHALL also be refused when the comparison key of its URI (see Filters) is that of an entry the list names or of a resource it hides, or when a template that matches it is hidden. The capabilities a server advertises SHALL NOT depend on the token. The policy SHALL apply alike on the server's route and on the aggregate endpoint, under the name the server gives the token.

#### Scenario: Tool lists per token

- **WHEN** the global tokens `laptop` and `phone` reach a server, and `phone` has the policy `tools: {allow: [echo]}`, `prompts: {allow: []}` and `resources: {allow: [fake://info, items]}` on it
- **THEN** `laptop` lists every tool, prompt, resource and template of the server; `phone` lists only `echo`, no prompts, `fake://info` and the template `items`, with the cache scope `private`, and reads `fake://items/7`

#### Scenario: Hidden entry like an unknown one

- **WHEN** `phone` of the scenario above calls `env`, gets the prompt `greet` or reads `fake://hidden`, all of which the server serves
- **THEN** each fails exactly as a call of a tool, a get of a prompt or a read of a resource the server does not have, and is logged with outcome `denied` and `tokenPolicy` `deny`

#### Scenario: Token policy on the aggregate endpoint

- **WHEN** `phone` has the policy `tools: {deny: [env]}` on `plain`, a member of the aggregate endpoint
- **THEN** `phone` does not list `plain__env` there and its call fails as one of `plain__nosuch`, logged with `server` `plain`, outcome `denied` and `tokenPolicy` `deny`, while `laptop` lists and calls it

### Requirement: Catalog mirror

Each server SHALL be served by one upstream MCP server whose catalog mirrors the downstream one. The gate SHALL list the tools, prompts, resources and resource templates the downstream advertises on every new downstream session, and the kinds it reports changed by list-changed notifications, which for a `2026-07-28` downstream that has not acknowledged its subscription means after every successful probe. A server that answers the resource template listing with "method not found" SHALL be taken to have no templates. A listing that fails SHALL keep the last catalog that was listed and be retried after 2 seconds, doubling up to 1 minute while the session lasts. A restart of the downstream SHALL keep the catalog until the new session has been listed. Entries that did not change SHALL stay registered as they are; a tool whose input schema is not a JSON object of type `object`, and an entry the SDK rejects, SHALL be skipped and logged, keeping its previous version if it had one. Clients that listen for changes SHALL be told when the mirrored lists change.

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

Every forwarded call, and every tool call or prompt get the SDK refuses before it is forwarded (with outcome `denied` when the name is not in the mirrored catalog, such as a tool the policy hides, or the token's policy hides it, and `error` otherwise), SHALL be logged as one line with the message `call` and the attributes `server`, `principal` (the token name, empty on a public server), `method`, the tool or prompt name or the resource URI (redacted and cut at 256 bytes), `durMs`, `outcome` (`ok`, `tool_error`, `error`, `denied`, `unavailable`, `withheld` or `input_required`), `tokenPolicy` (what the token's policy on the server decided: `none` without one, `allow` or `deny`; a call the token's policy hides has outcome `denied`) and `redactions`, the number of findings replaced and files withheld. Arguments and results SHALL NOT be logged. With `log.requests`, each HTTP request to the server's route SHALL be logged with its method, status, duration and remote address, but not its path, query or headers. Behind a proxy, the remote address SHALL be the right-most `X-Forwarded-For` entry that is not in `listen.trustedProxies`, read only when the peer is in it. The SDK's informational lines, which it writes for every session and so for every stateless request, SHALL be logged at debug level.

#### Scenario: Audit line

- **WHEN** a client holding the token `laptop` calls `echo` and one secret is redacted
- **THEN** the `call` line has `principal` `laptop`, `tool` `echo`, `outcome` `ok`, `tokenPolicy` `none` and `redactions` 1

### Requirement: Health

`GET` and `HEAD` of `/_healthz` and `/_readyz` SHALL need no token and answer on any Host; other methods SHALL get 405. GET SHALL return a JSON object with `name` (the config's `name`), `serverCount` (the enabled servers), `status`, `unhealthy` (only when not empty), `needsLogin` (only when not empty) and `version` (the build's), HEAD only the status code. `/_healthz` SHALL be 200 `ok` while the process serves. `/_readyz` SHALL be 503 `initializing` until every enabled server has had its catalog listed or is in `needs-login`, or `startupGracePeriod` has passed since start; then 503 `degraded`, naming them sorted in `unhealthy`, while any server whose catalog was listed is in a state other than `ready` and `degraded`; 503 `unavailable` when servers are enabled but none was ever listed; 503 `degraded` while any server is in `needs-login`; and 200 `ok` otherwise. After startup, `needsLogin` SHALL name, sorted, every server in `needs-login`, whether its catalog was listed or not.

#### Scenario: Startup and degradation

- **WHEN** a gate with a good server, a failing server and an HTTP server starts with a 1 second grace period, and the HTTP server later goes down and comes back
- **THEN** `/_readyz` is `initializing`, then `ok` after the grace period, then `degraded` naming the HTTP server, then `ok` again, while `/_healthz` is `ok` throughout

#### Scenario: Server waiting for a login

- **WHEN** a gate has a stdio server and an OAuth server without a grant, with a 30 second grace period
- **THEN** `/_readyz` is soon 503 `degraded` with `needsLogin` naming the OAuth server, its route answers 503, `/_status` shows it `needs-login`; once a grant is saved it connects, serves calls and `/_readyz` is `ok`; once the grant is revoked a call fails and it is `needs-login` again

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
