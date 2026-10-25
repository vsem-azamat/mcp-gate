# downstream-lifecycle Specification

## Purpose

A supervisor keeps one downstream MCP server connected: it starts a stdio server as a child process or connects to an HTTP server, negotiates the protocol version, bounds message sizes, probes the server, and restarts it after a failure. One supervisor serves every call to its server. `mcp-gate check -connect` uses it to try every server of a config.

## Requirements

### Requirement: States

A supervised server SHALL be in one of the states `starting`, `ready`, `degraded`, `backoff`, `disabled` and `stopped`. A disabled server SHALL never be started. Calls SHALL go through only in `ready` and `degraded`; in any other state a call SHALL fail at once with an error naming the state. Each call SHALL be bounded by `callTimeout` when it is not zero.

#### Scenario: Call during backoff

- **WHEN** a call is made while the server waits to restart
- **THEN** it fails at once with a not-ready error naming `backoff`

#### Scenario: Call timeout

- **WHEN** `callTimeout` is `100ms` and the server never answers a call
- **THEN** the call fails with a deadline error and the server stays usable

### Requirement: Protocol version

Without a pin, the supervisor SHALL offer the latest protocol version, letting the SDK try `server/discover` and fall back to `initialize`, and SHALL give that whole handshake 5 seconds. When those 5 seconds pass without an answer, it SHALL tear the attempt down (ending a stdio child) and reconnect offering `2025-11-25`. When that pinned handshake completes within 5 seconds, the server ignored discover: the supervisor SHALL keep the automatic pin for later connects and report it once, so that it can be stored. When it takes longer, the server was only slow, and its next connect SHALL offer the latest version again. Either way the session SHALL be reported as automatically pinned. A `protocolVersion` set in the config SHALL be offered instead, with no discover sub-deadline. The negotiated version SHALL be reported.

#### Scenario: Version matrix

- **WHEN** servers supporting only one of `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25` and `2026-07-28` are reached over stdio, HTTP with event streams and HTTP with JSON responses
- **THEN** each connects with its version and serves calls

#### Scenario: Server ignores discover

- **WHEN** a server never answers `server/discover`
- **THEN** it is connected pinned to `2025-11-25`, and the automatic pin is kept and reported once

#### Scenario: Slow start

- **WHEN** a stdio server needs longer than the sub-deadline before it reads its input
- **THEN** it is connected on the pin for this session, and the pin is not kept

#### Scenario: Manual pin

- **WHEN** `protocolVersion: 2025-06-18` is set for a server that supports every version
- **THEN** the session runs on `2025-06-18`

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

A stdio frame, an HTTP response body and an event of an HTTP event stream SHALL each be limited to `maxMessageBytes`. A message over the limit SHALL be dropped without holding more than the limit in memory; when it is a response (a top-level `result` or `error` before any `method`) whose id names a pending request, that request SHALL fail with a JSON-RPC error saying the response exceeded `maxMessageBytes`, and the session and every other request SHALL go on. On stdio, a line that is not a JSON-RPC message SHALL be skipped. Redirects SHALL NOT be followed, and gzip-encoded responses SHALL be decoded before the limit applies.

#### Scenario: Oversized stdio response

- **WHEN** a stdio server answers one call with 1 MiB while `maxMessageBytes` is 64 KiB and another call is running
- **THEN** that call fails with the size error, the other call succeeds, and the same child keeps serving

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

### Requirement: check -connect

`mcp-gate check -connect <file>` SHALL, after validating the file, supervise every enabled server at once, wait up to `-timeout` (default 60s) for each to become ready or fail, print one line per server (its protocol version, whether it was pinned automatically, and its number of tools; `disabled`; or the redacted error) and stop them all. The exit status SHALL be 0 when every enabled server connected and 2 otherwise.

#### Scenario: Mixed servers

- **WHEN** a config has a stdio server, a stdio server that ignores discover, an HTTP server and a disabled server
- **THEN** each line reports its server, the second one pinned automatically, and the exit status is 0

#### Scenario: Server that cannot start

- **WHEN** a stdio server exits at once
- **THEN** its line reports the failure and the exit status is 2
