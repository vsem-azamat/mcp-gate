# serving Specification

## Purpose

`mcp-gate serve` puts the downstream servers of a config behind one HTTP listener. Each enabled server is served at `/<name>/mcp` over stateless streamable HTTP, behind named bearer tokens, and optionally many of them together at `/mcp`, with its catalog mirrored from the one supervised downstream session and filtered by the server's policy and, per token, by the token's policy. Calls are forwarded to that session with progress, cancellation and `_meta` handled per call, and their results are redacted, failing closed, with the files of download tools scanned (see the file-scanning spec) and the secrets kept in the escrow when it is on (see the escrow spec). The gate reports liveness, readiness and status, and writes one audit line per call.

## Requirements

### Requirement: serve

`mcp-gate serve [-state-dir DIR] <config.yaml>` SHALL load the config as `check` does and exit with status 2, printing every problem, when it is invalid, and also when the escrow key hash cannot be resolved (see the escrow spec). Otherwise it SHALL make itself non-dumpable and a child subreaper, start a supervisor for every enabled server (OAuth servers with the grants in the `oauth` directory of the state directory, see the oauth spec), listen on `listen.addr`, and log JSON lines to stderr at `logLevel` and above. When systemd passes it a socket (`LISTEN_FDS` set and `LISTEN_PID` naming the gate's process), it SHALL serve that socket instead of opening `listen.addr`, logging a warning when the socket is on another address; more than one socket, or one that is not a listening TCP socket, SHALL make it exit with status 2. When `NOTIFY_SOCKET` is set it SHALL send `READY=1` there once startup is over (see Health) and `STOPPING=1` when it begins to shut down. SIGHUP reloads the config (see Reload). Neither these variables nor the passed socket SHALL reach the stdio servers. On SIGINT or SIGTERM it SHALL stop accepting connections, leaving those that wait on a socket systemd holds to the next process, end the `subscriptions/listen` streams, and for up to 1 second still serve the requests that arrive on open connections, answering each request from then on with `Connection: close`; it SHALL then close the connections that are idle or on which no request has arrived, give calls in flight up to 10 seconds from the start of the shutdown (their progress still delivered), stop every server in parallel, logging one that does not stop within 15 seconds, and exit with status 0; it SHALL exit with status 2 when it cannot listen or the listener fails.

#### Scenario: Shutdown with a listening client

- **WHEN** a `2026-07-28` client listens for changes and another runs a call with progress while the gate gets SIGTERM
- **THEN** the shutdown does not wait for the listening client, and the call completes with its progress

#### Scenario: Shutdown with an unused connection

- **WHEN** a client has opened a connection but sent no request on it when the gate gets SIGTERM
- **THEN** the gate closes that connection and does not wait for it

#### Scenario: Request on an idle connection at shutdown

- **WHEN** a client sends a request on a kept-alive connection just after the gate gets SIGTERM
- **THEN** the request is answered with `Connection: close` and the connection then closed, rather than the connection being closed under it

#### Scenario: Restart on a socket systemd holds

- **WHEN** clients call tools without pause, with retries off, on sessions opened before the restart and on new connections, while a slow call is in flight, and the gate serving a socket passed by systemd gets SIGTERM and a new gate is started on the same socket
- **THEN** no connection is refused and no call fails: the slow call completes, calls made while no gate runs wait in the socket's queue and are answered by the new gate once its server is up, and the sessions opened before the restart go on calling without initializing again

#### Scenario: Readiness notification

- **WHEN** a gate with `NOTIFY_SOCKET` set starts, its server connects, and it gets SIGTERM
- **THEN** it sends `READY=1` once the server has connected, not before, and `STOPPING=1` at the shutdown

#### Scenario: Invalid config

- **WHEN** `serve` is given a config whose server accepts no token
- **THEN** it exits with status 2, naming `servers.<name>.auth`

### Requirement: Reload

On SIGHUP `serve` SHALL load its config file again, with the environment it started with, and apply it without a restart; a SIGHUP that arrives before the servers were started SHALL be applied once they are. With `NOTIFY_SOCKET` set, once startup is over (see Health), it SHALL send `RELOADING=1` with `MONOTONIC_USEC` when a reload begins and `READY=1` when it is over, whether or not the config was applied; a reload during startup SHALL send neither, and one after the shutdown began SHALL be skipped. A config that does not load or pass validation SHALL be rejected with an error line, and the gate SHALL go on with the config it has; `check` SHALL accept exactly the configs a reload applies.

A valid config SHALL be applied as a whole, at one instant: every request that arrives from then on SHALL be served under the new config, and a request in flight SHALL finish under the config it arrived under, its tokens, filters, redaction and request logging, so that no request sees part of one config and part of another. What a change of each config key does SHALL be one of:

- **Restart of the server**: the server's `stdio` or `http` with every key under them, `callTimeout`, `maxMessageBytes`, `protocolVersion`, `probeInterval`, `restart` and `disabled`, and the config's `name`, which servers get as the client name. The server SHALL be stopped once the requests in flight on the routes that reach it, under this or an earlier config, have ended, at most 10 seconds after the reload, and then started with the new settings; meanwhile its calls SHALL fail as while a server restarts, and its catalog stays listed. A removed or disabled server SHALL be stopped the same way. A server that is new SHALL start only after those stops, so that two processes of a stdio server never run together.
- **In place, new mirror**: a server's `tools`, `prompts`, `resources`, `redact`, `forwardMeta` and `maxMessageBytes`, the token policies on the server (`policies`), and `escrow.ttl`. The server SHALL keep running, its catalog served under the new settings at once (prompts or resources that were hidden by every policy until then once they have been listed), and the `subscriptions/listen` streams of the routes that reach it SHALL end.
- **In place, new routes**: `auth`, a server's `auth` and `log`, `aggregate`, `listen.behindProxy`, `listen.trustedProxies` and `listen.allowedHosts`. The routes whose inputs change SHALL be replaced and their `subscriptions/listen` streams SHALL end; routes whose inputs do not change SHALL keep their streams.
- **In place**: `logLevel`, `admin`, and `name` for the health endpoints.
- **At the next restart only**: `listen.addr`, `startupGracePeriod`, and `escrow` but `escrow.ttl`; a reload that changes them SHALL log a warning naming them.

The gate SHALL log one `config reloaded` line naming the servers added, restarted, removed and kept.

#### Scenario: Invalid config on reload

- **WHEN** the config file is replaced by one that fails validation and the gate gets SIGHUP
- **THEN** it logs an error, keeps serving under the old config, and sends `RELOADING=1` then `READY=1`

#### Scenario: Token revoked by a reload

- **WHEN** a reload removes a token while a call made with it is in flight
- **THEN** the call completes, and every request with the token from then on gets 401, while other tokens keep working

#### Scenario: Server kept by a reload

- **WHEN** a reload adds a `tools.deny` entry and turns redaction off for a server whose `stdio` is unchanged
- **THEN** the server keeps its process, the denied tool is no longer listed, and a result holding a password is no longer redacted

#### Scenario: Server changed by a reload

- **WHEN** a reload changes a stdio server's `env` while a call to it is in flight
- **THEN** the call completes, and the server is then restarted with the new environment and serves calls again

#### Scenario: Token policy changed by a reload

- **WHEN** a token has a policy on a server allowing one tool, and a reload changes it to allow another
- **THEN** the token lists and calls only the newly allowed tool from then on, on the server's route and on `/mcp`, while other tokens keep the server's whole catalog and the server keeps its process

#### Scenario: Route kept by a reload

- **WHEN** a client listens for changes on one server's route and a reload changes only another server's filters
- **THEN** the client's stream goes on, and it is told of a later change of its server's catalog

#### Scenario: Call under an older config

- **WHEN** a call is in flight on a route that a first reload replaced, and a second reload changes the server's environment
- **THEN** the server is restarted only after the call completes

#### Scenario: Reload during startup

- **WHEN** the gate gets SIGHUP while its server is still starting, and again after startup
- **THEN** the first reload applies without a notification, `READY=1` follows the end of startup, and the second reload sends `RELOADING=1` and then `READY=1`

#### Scenario: Servers added and removed by a reload

- **WHEN** a reload removes one server and adds another
- **THEN** the removed server's process ends, its route answers 404 and `/_status` no longer lists it, and the added server starts and serves calls

### Requirement: Routes

Each enabled server SHALL be served at exactly `/<name>/mcp`; any other path, including the route of a disabled server, SHALL get 404, except `/mcp` when the aggregate endpoint is on (see Aggregate endpoint), `/_healthz`, `/_readyz`, `/_status` and, with the escrow on and `escrow.tcp` true, the escrow API under `/_escrow/`, which none of the route checks below apply to. A route SHALL run, in this order: the Host check, the token check, cross-origin protection, a 503 with `Retry-After: 5` while the server's catalog has never been listed, a request body limit of 4 MiB (413) read within 30 seconds (408), and the SDK's stateless streamable HTTP handler, which answers GET with 405. Until startup is over (see Health), a request to a server whose catalog has never been listed and that is not in `needs-login` SHALL be held until the catalog is listed, the server is in `needs-login`, or startup ends, and only then answered or refused with the 503, so that a client of a gate that has just started is not refused while the server connects. Sessions SHALL survive a restart of the gate: the handler keeps no session, so a client that initialized with one gate process SHALL go on calling another without initializing again. A POST holding one JSON-RPC call SHALL be answered with `application/json` when its client accepts `application/json`, it is not `subscriptions/listen`, and its params carry no `_meta.progressToken` unless the client accepts only `application/json`; a batch, a `subscriptions/listen` request and a request with a progress token SHALL be answered with a `text/event-stream`, as SHALL a request whose client accepts `text/event-stream` but not `application/json`. A client that accepts only one of the two types (counting `*/*`, `application/*` and `text/*`, and not a type given `q=0`, which a wildcard does not override) SHALL get that one, a request with a progress token then losing its progress when it is `application/json`; `subscriptions/listen` without `text/event-stream`, and any request accepting neither, SHALL get 400. Notifications and responses from the client SHALL get 202 with no body. When `listen.allowedHosts` is set, a request whose Host is not in it (an entry without a port matching any port, without regard to case) SHALL get 403. Unless `listen.behindProxy` is set, the SDK's DNS-rebinding check SHALL reject a request to a loopback listener whose Host is not a loopback name. A panic in an HTTP handler SHALL be answered with 500, and a panic while handling an MCP request or a notification with an internal JSON-RPC error or nothing; either SHALL be logged by its type, without its value. The listener SHALL bound request headers to 64 KiB read within 10 seconds and close idle connections after 120 seconds, and SHALL NOT bound the time a call takes. Each write of a response, of at most 64 KiB, SHALL fail when it has not completed within 30 seconds; the connection is then closed and the request's context cancelled, which cancels its call, so a client that stops reading cannot hold the gate's resources while the connection stays up. This holds for the escrow API and the socket as well.

#### Scenario: Server not connected yet

- **WHEN** a client with a valid token posts to the route of a server that has not connected, during and after startup
- **THEN** it gets 503 with `Retry-After: 5` once startup is over, at once after it, and without a token it gets 401

#### Scenario: Call during startup

- **WHEN** a client connects to the route of a server that takes 700 milliseconds to start, right after the gate starts, and calls a tool
- **THEN** its requests are held until the server is up, and the call succeeds

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

With `aggregate` set, the gate SHALL also serve the servers of `aggregate.servers` (every enabled server by default) together at exactly `/mcp`, which no server route can be, through the same chain as a server route with these differences. A request SHALL reach a member exactly when that member's own route would accept its `Authorization` header: a public member always, any other when the token is one the member accepts. A request without the header SHALL reach the public members; a request whose credential no member accepts, or that reaches no member, SHALL get 401 with the body `Unauthorized`, even when there are public members. A request that arrives before startup is over (see Health) SHALL be held until every member it reaches has had its catalog listed or is in `needs-login`, or startup ends, and then served.

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

`tools`, `prompts` and `resources` SHALL each be an allow list or a deny list. Tools and prompts SHALL be matched by name; resources by URI or name, and resource templates by URI template or name. An entry SHALL pass an allow list when any of its keys is listed and fail a deny list when any of its keys is listed. A tool allow list that is empty SHALL filter nothing; an empty prompt or resource allow list SHALL expose none, and the capability SHALL NOT be advertised. A call of a tool or a get of a prompt that is filtered out SHALL fail. Under a resource deny list, a read SHALL be refused when the comparison key of its URI is the key of a listed entry or of the URI of a resource the list hides, so that a template does not reach a hidden resource by another spelling, and when a template the list hides matches the URI, since the server may serve it through that template. The key SHALL decode every percent-encoding until none is left, drop the query and the fragment, lower-case the scheme and the authority, drop user information, a port and a trailing dot from the authority and a `localhost` authority, and take the authority and path as one path in which `;` parameters, surrounding spaces and NULs, and empty and `.` segments are dropped and `..` segments resolved, so that the number of slashes after the scheme does not matter. A deny list matches spellings, not what a server makes of them, so it is a best effort; an allow list is the boundary. Under an allow list, a read SHALL reach only an allowed resource or a resource through an allowed template, and SHALL be refused when the comparison key of its URI is that of the URI of a listed resource the list does not allow: whatever its query when that URI has none, and, when it has one, when the read's query holds each of its parameters, compared decoded, split at `&` and `;`, with `+` as a space, keys and values trimmed and lower-cased, digit values without leading zeros, empty parameters ignored and repetition counting as presence, so that hiding `db://t?id=1` refuses `db://t?ID=01&x=y` but not `db://t?id=2`; a template may still match URIs of resources the server does not list. One algorithm SHALL decide reads under a server's resource filter and under a token's.

#### Scenario: Allow lists

- **WHEN** a server allows the tools `echo` and `sleep`, no prompts, and the resource `fake://info` and the template `items`
- **THEN** it lists those two tools and that resource, does not advertise prompts, refuses a call of another tool with a `denied` audit line and a read of another resource, and reads `fake://items/7` through the template

#### Scenario: Deny list and templates

- **WHEN** a server denies `fake://hidden` and also serves the template `fake://{+path}`
- **THEN** reads of `fake://hidden`, `FAKE://hidden`, `fake://%68idden`, `fake://hidden#x`, `fake://hidden/`, `fake://hidden?`, `fake:///hidden` and `fake://x/../hidden` are refused and `fake://other` is read through the template

#### Scenario: Hidden template and hidden spelling

- **WHEN** a server denies the template `items` (`fake://items/{id}`) and also serves `fake://{+path}`, and another allows only `fake://{+path}` and `fake://info` while listing `fake://hidden`
- **THEN** the first refuses `fake://items/7` and reads `fake://other`; the second reads `fake://other` and `fake://info` and refuses `fake://hidden` and `FAKE://%68idden`

### Requirement: Token policies

A token with a policy on a server (`policies.<token>.servers.<server>`) SHALL see and reach only what both the server's filters and the policy's pass. The policy's filters SHALL be matched as a server's filters of the same kind, and `none` SHALL hide every entry of its kind; a filter the policy leaves out, and a server it does not name, SHALL narrow nothing. The token SHALL be served an upstream server of its own holding only what the policy passes, so that its lists, their pagination, list-changed notifications and every check the SDK makes before a handler know nothing of a hidden entry. On a server where any token has a policy, results SHALL carry the cache scope `private`, on the aggregate endpoint too. A tool call or prompt get of an entry the policy hides SHALL fail with the error of a name the server does not have, so that a token cannot tell a hidden tool or prompt from a missing one, and a resource read of a URI the policy does not pass with the error of an unknown resource. A hidden resource is not as well hidden: when a template the policy passes also matches its URI, its read fails while other URIs through that template succeed, so its URI can be found by guessing. A read SHALL pass when the resource the server lists under its URI passes, or, when none is listed, under an allow list a template that matches it passes and under a deny list no template that matches it is hidden; it SHALL also be refused when the comparison key of its URI (see Filters) is that of a listed resource the policy hides or, under a deny list, of an entry the list names. Such a refused read SHALL be logged like a refused call, whereas a read of a URI the server does not serve is not logged. The `tokenPolicy` of an audit line SHALL be `none` for a name the mirrored catalog does not hold or a URI it does not serve in any spelling, such as one the server's own filter hides, since no policy decided it. The capabilities a server advertises SHALL NOT depend on the token. The policy SHALL apply alike on the server's route and on the aggregate endpoint, under the name the server gives the token.

#### Scenario: Tool lists per token

- **WHEN** the global tokens `laptop` and `phone` reach a server, and `phone` has the policy `tools: {allow: [echo]}`, `prompts: none` and `resources: {allow: [fake://info, items]}` on it
- **THEN** `laptop` lists every tool, prompt, resource and template of the server; `phone` lists only `echo`, no prompts, `fake://info` and the template `items`, and reads `fake://items/7`; both lists carry the cache scope `private`, while those of a server without policies carry `public`

#### Scenario: Hidden entry like an unknown one

- **WHEN** `phone` of the scenario above calls `env`, gets the prompt `greet` or reads `fake://hidden`, all of which the server serves
- **THEN** each fails exactly as a call of a tool, a get of a prompt or a read of a resource the server does not have, also for a `2026-07-28` call of a hidden tool with a header-bound parameter, and is logged with outcome `denied` and `tokenPolicy` `deny`, while a call of `nosuch`, or of a tool the server's own filter hides, is logged `denied` with `tokenPolicy` `none`

#### Scenario: Token policy on the aggregate endpoint

- **WHEN** `phone` has the policy `tools: {deny: [env]}` on `plain`, a member of the aggregate endpoint
- **THEN** `phone` does not list `plain__env` there and its call fails as one of `plain__nosuch`, logged with `server` `plain`, outcome `denied` and `tokenPolicy` `deny`, while `laptop` lists and calls it

### Requirement: Catalog mirror

Each server SHALL be served by one upstream MCP server whose catalog mirrors the downstream one, and by one more for each token with a policy on it (see Token policies). The gate SHALL list the tools, prompts, resources and resource templates the downstream advertises on every new downstream session, and the kinds it reports changed by list-changed notifications, which for a `2026-07-28` downstream that has not acknowledged its subscription means after every successful probe. A server that answers the resource template listing with "method not found" SHALL be taken to have no templates. A listing that fails SHALL keep the last catalog that was listed and be retried after 2 seconds, doubling up to 1 minute while the session lasts. A restart of the downstream SHALL keep the catalog until the new session has been listed. Entries that did not change SHALL stay registered as they are; a tool whose input schema is not a JSON object of type `object`, and an entry the SDK rejects, SHALL be skipped and logged, keeping its previous version if it had one. Clients that listen for changes SHALL be told when the mirrored lists change.

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
