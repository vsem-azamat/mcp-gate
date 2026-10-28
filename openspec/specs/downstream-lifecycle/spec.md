# downstream-lifecycle Specification

## Purpose

A supervisor keeps one downstream MCP server connected: it starts a stdio server as a child process or connects to an HTTP server, over streamable HTTP or the legacy HTTP+SSE transport, negotiates the protocol version, bounds message sizes, probes the server, and restarts it after a failure. One supervisor serves every call to its server. `mcp-gate serve` runs one per enabled server, and `mcp-gate check -connect` uses them to try every server of a config.

## Requirements

### Requirement: States

A supervised server SHALL be in one of the states `starting`, `ready`, `degraded`, `backoff`, `needs-login`, `disabled` and `stopped`. A disabled server SHALL never be started. Calls SHALL go through only in `ready` and `degraded`; in any other state a call SHALL fail at once with an error naming the state. Each call SHALL be bounded by `callTimeout` when it is not zero. Stopping the supervisor SHALL cancel the calls in flight.

#### Scenario: Call during backoff

- **WHEN** a call is made while the server waits to restart
- **THEN** it fails at once with a not-ready error naming `backoff`

#### Scenario: Call timeout

- **WHEN** `callTimeout` is `100ms` and the server never answers a call
- **THEN** the call fails with a deadline error and the server stays usable

### Requirement: OAuth

An HTTP server with an `oauth` block SHALL authorize its requests with its grant as the oauth spec requires. Before each connect attempt the supervisor SHALL check for a usable grant; without one it SHALL enter `needs-login`, record the error `OAuth login required (<reason>): run mcp-gate auth login <config> <name>`, log it once rather than on every attempt, send nothing to the server, and try again after the backoff, which counts as no restart, staying in `needs-login` while there is no usable grant. A connect that fails because the grant was rejected SHALL do the same. When a call fails and the grant is no longer usable, the server SHALL be probed at once, and a failed probe with the grant unusable SHALL close the session without waiting for more failures, so that the server enters `needs-login`.

#### Scenario: No grant, then a login

- **WHEN** an OAuth server has no grant, and one is saved while the supervisor runs
- **THEN** it is `needs-login` with the login command in its error, calls fail naming `needs-login`, no request reaches the server, and it then becomes `ready`

#### Scenario: Grant revoked mid-session

- **WHEN** the authorization server revokes the grant of a connected server
- **THEN** the server becomes `needs-login`, its error names `invalid_grant` and no token

### Requirement: Protocol version

Without a pin, the supervisor SHALL offer the latest protocol version, letting the SDK try `server/discover` and fall back to `initialize`, and SHALL give that whole handshake 5 seconds. When those 5 seconds pass without an answer, it SHALL tear the attempt down (ending a stdio child) and reconnect offering `2025-11-25`. When that pinned handshake completes within 5 seconds, the server ignored discover: the supervisor SHALL keep the automatic pin for later connects and report it once, so that it can be stored. When it takes longer, the server was only slow, and its next connect SHALL offer the latest version again. Either way the session SHALL be reported as automatically pinned. A `protocolVersion` set in the config SHALL be offered instead, with no discover sub-deadline. A server reached over the legacy HTTP+SSE transport (`transport: sse`) SHALL be offered `2025-11-25` with `initialize` when it has no pin, with no discover and no sub-deadline, and its session SHALL NOT be reported as automatically pinned. The negotiated version SHALL be reported.

#### Scenario: Version matrix

- **WHEN** servers supporting only one of `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25` and `2026-07-28` are reached over stdio, HTTP with event streams and HTTP with JSON responses, and servers supporting only one of the versions before `2026-07-28` over the legacy HTTP+SSE transport
- **THEN** each connects with its version, is not reported as automatically pinned, and serves calls

#### Scenario: Server ignores discover

- **WHEN** a server never answers `server/discover`
- **THEN** it is connected pinned to `2025-11-25`, and the automatic pin is kept and reported once

#### Scenario: Slow start

- **WHEN** a stdio server needs longer than the sub-deadline before it reads its input
- **THEN** it is connected on the pin for this session, and the pin is not kept

#### Scenario: Manual pin

- **WHEN** `protocolVersion: 2025-06-18` is set for a server that supports every version
- **THEN** the session runs on `2025-06-18`

### Requirement: Legacy HTTP+SSE transport

An `http` server with `transport: sse` SHALL be reached over the HTTP+SSE transport of protocol `2024-11-05`: a GET to `url` opens an event stream whose first event names the endpoint that messages are POSTed to, and every message from the server arrives on that stream. The message endpoint SHALL be on the origin (scheme, host and port) of `url`; a request to any other origin SHALL NOT be sent, so that neither the configured headers nor an OAuth token leave for a host the operator did not name, and the connect SHALL fail. The configured headers, OAuth tokens (refreshed after a 401 and the request sent once more), the size limits, redirects not followed, probes and restarts SHALL be as for streamable HTTP. An event of the stream over `maxMessageBytes` SHALL be dropped, and when it is a response whose id names a pending request, that request SHALL fail with the size error while the session goes on. A recorded error SHALL name any URL on the host of `url`, on any port and in any spelling of the host the origin check would compare equal or refuse, such as the message endpoint with its session id and a URL glued onto another, as `<servers.NAME.http.url>`, query and all, and the URLs last requested of the server SHALL be replaced as they were sent, whatever characters their query holds. The time this takes SHALL grow linearly with the length of the error.

#### Scenario: Legacy server

- **WHEN** a server that speaks only the HTTP+SSE transport and protocol `2024-11-05` is configured with `transport: sse`
- **THEN** it connects on `2024-11-05` without sending `server/discover`, and serves calls and list-changed notifications

#### Scenario: Session id in an error

- **WHEN** a POST to the SDK's own message endpoint, the stream's URL with `?sessionid=` added, fails
- **THEN** the recorded error names `<servers.NAME.http.url>` and holds no part of the session id

#### Scenario: Message endpoint on another origin

- **WHEN** the first event of a legacy server's stream names a message endpoint on another host
- **THEN** no request reaches that host, the server does not become ready, and its error says the endpoint is on another origin

#### Scenario: Oversized legacy response

- **WHEN** a legacy server answers a call with 1 MiB while `maxMessageBytes` is 64 KiB
- **THEN** that call fails with the size error and the same session keeps serving

#### Scenario: Legacy server behind OAuth

- **WHEN** a legacy server takes only OAuth access tokens and the server has a grant, which is later revoked
- **THEN** its requests carry the access token and calls succeed, and after the revocation it becomes `needs-login`

#### Scenario: Legacy server down and up

- **WHEN** a legacy server answers 503 for a while and then recovers
- **THEN** the server goes through `backoff` and becomes `ready` again on a new stream

### Requirement: Stdio children

A stdio server SHALL be started directly, without a shell, in a process group of its own, with the configured `cwd`, and with an environment made only of the gate's variables named by `inheritEnv` and the variables in `env`, which win. The child's `oom_score_adj` SHALL be set to 500. The child's stderr SHALL be logged line by line after redaction, rate limited, with lines over 4 KiB cut, and the last 64 KiB of lines SHALL be kept for status.

Stopping a child SHALL close its stdin, send SIGTERM to its process group, wait up to 5 seconds for the leader and every member of the group to exit, then send SIGKILL to the group and wait again. A restart SHALL begin only after the group is gone, or after the wait following SIGKILL, which is logged as an error. The gate SHALL make itself non-dumpable (`PR_SET_DUMPABLE` 0) and a child subreaper that reaps the orphans reparented to it.

#### Scenario: Clean environment

- **WHEN** the gate's environment holds `GATE_SECRET` and the child inherits only `PATH` and `LC_*`
- **THEN** the child sees `PATH`, its `LC_*` variables and its `env`, and not `GATE_SECRET`

#### Scenario: Grandchild ignoring SIGTERM

- **WHEN** a child that ignores SIGTERM and has started a grandchild in its group is stopped
- **THEN** both are gone when the stop returns

#### Scenario: Secret on stderr

- **WHEN** a child writes a GitHub token to stderr
- **THEN** neither the log nor the kept lines contain it

#### Scenario: Gate memory

- **WHEN** a process of the same user reads the non-dumpable gate's `/proc/<pid>/environ`
- **THEN** the read fails

### Requirement: Message size

A stdio frame (a line without its line ending, `\n` or `\r\n`), an HTTP response body and an event of an HTTP event stream SHALL each be limited to `maxMessageBytes`. A message over the limit SHALL be dropped without holding more than the limit in memory (plus the line ending of a stdio frame); when it is a response (a top-level `result` or `error` before any `method`) whose id names a pending request, that request SHALL fail with a JSON-RPC error saying the response exceeded `maxMessageBytes`, and the session and every other request SHALL go on. On stdio, a line that is not a JSON-RPC message SHALL be skipped. Redirects SHALL NOT be followed, and gzip-encoded responses SHALL be decoded before the limit applies.

#### Scenario: Oversized stdio response

- **WHEN** a stdio server answers one call with 1 MiB while `maxMessageBytes` is 64 KiB and another call is running
- **THEN** that call fails with the size error, the other call succeeds, and the same child keeps serving

#### Scenario: Stdio frame of exactly the limit

- **WHEN** a stdio server writes a frame of exactly `maxMessageBytes` bytes followed by its newline
- **THEN** the frame is delivered; a frame one byte longer is dropped

#### Scenario: Oversized HTTP response

- **WHEN** an HTTP server answers a call with more than `maxMessageBytes`, as JSON or as an event, compressed or not
- **THEN** that call fails with the size error and the session keeps serving

### Requirement: Probes

Every `probeInterval` the supervisor SHALL probe the server, with `ping` on sessions before `2026-07-28` and a tools list on later ones, unless a call is in flight. A probe that overlapped a call SHALL NOT count. A JSON-RPC error reply SHALL count as alive. Any other failure (no answer within 10 seconds or the interval, whichever is shorter, or a transport error, including an HTTP status the SDK retries, such as 503) SHALL make the server `degraded`; a successful probe SHALL make it `ready` again. After 3 failed probes in a row with no call in flight, the session SHALL be closed and the server restarted.

#### Scenario: Long call on a single-threaded server

- **WHEN** a server that handles one request at a time runs a call longer than several probe intervals
- **THEN** no probe is sent during the call and the server is not restarted

#### Scenario: Error reply

- **WHEN** a server answers every probe with a JSON-RPC error
- **THEN** it stays `ready`

#### Scenario: Frozen server

- **WHEN** a server stops answering
- **THEN** it becomes `degraded`, then is restarted

### Requirement: Restarts

When the child exits, the connection closes, or the probes fail as above, the supervisor SHALL record the error, with the server's URL replaced by its config path and then redacted; go to `starting`, so that no new call starts on the old session; end the old session and child; wait in `backoff`; and connect again. The first wait SHALL be 1 second, doubling after each failure up to `restart.maxBackoff`; a session that stayed up for a minute SHALL reset it. A failure to start or connect SHALL be retried the same way. The number of restarts SHALL be reported.

#### Scenario: URL with a secret

- **WHEN** an HTTP server whose URL holds a secret in its path cannot be reached
- **THEN** the recorded error names `<servers.NAME.http.url>` instead of the URL

#### Scenario: Crash

- **WHEN** a stdio child exits during a call
- **THEN** the call fails, and a new child is started and becomes `ready`

#### Scenario: HTTP server down and up

- **WHEN** an HTTP server answers 503 for a while and then recovers
- **THEN** the server goes through `degraded` and `backoff`, then becomes `ready` again

### Requirement: Notifications

The supervisor SHALL pass the server's progress notifications, log messages and list-changed notifications to handlers given in its options, which must not block. When list-changed handlers are given, a session from `2026-07-28` SHALL subscribe with `subscriptions/listen` to the changes the server offers; until the server acknowledges the subscription, every list-changed handler SHALL be called after each successful probe instead, so that a server that rejects it still has its changes noticed. Each new session SHALL be reported once it serves calls, so that its catalog can be listed.

#### Scenario: Rejected subscription

- **WHEN** a `2026-07-28` server that offers list changes answers `subscriptions/listen` with an error
- **THEN** the session serves calls and the list-changed handlers are called after each successful probe

#### Scenario: Acknowledged subscription

- **WHEN** a `2026-07-28` server acknowledges the subscription, over stdio or HTTP
- **THEN** the list-changed handlers are called only when the server reports a change

#### Scenario: Progress

- **WHEN** a call's tool sends progress notifications for the call's token
- **THEN** the progress handler receives them while the call runs

### Requirement: check -connect

`mcp-gate check -connect [-state-dir DIR] <file>` SHALL, after validating the file, supervise every enabled server at once, OAuth servers with the grants of the state directory (by default the first entry of `$STATE_DIRECTORY`), wait up to `-timeout` (default 60s) for each to become ready, fail or need a login, print one line per server (its protocol version, whether it was pinned automatically, and its number of tools; `disabled`; the login error; or the redacted error) and stop them all. The exit status SHALL be 0 when every enabled server connected and 2 otherwise.

#### Scenario: Mixed servers

- **WHEN** a config has a stdio server, a stdio server that ignores discover, an HTTP server and a disabled server
- **THEN** each line reports its server, the second one pinned automatically, and the exit status is 0

#### Scenario: OAuth server without a grant

- **WHEN** an OAuth server has no grant in the state directory
- **THEN** its line names the `mcp-gate auth login` command and the exit status is 2

#### Scenario: Server that cannot start

- **WHEN** a stdio server exits at once
- **THEN** its line reports the failure and the exit status is 2
