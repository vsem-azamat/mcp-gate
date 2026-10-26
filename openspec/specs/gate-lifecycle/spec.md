# gate-lifecycle Specification

## Purpose

`mcp-gate serve` runs the gate: it loads a config, starts a supervisor for every enabled server, listens (on a socket systemd passes, or on `listen.addr`), tells systemd when it is ready and when it stops, and shuts down giving the calls in flight a grace period. It reports liveness, readiness and status, and keeps the protocol pins it learns. What it serves is in the serving, routes-and-auth, aggregate-endpoint and token-policies specs; how it applies a changed config is in the reload spec.

## Requirements

### Requirement: serve

`mcp-gate serve [-state-dir DIR] <config.yaml>` SHALL load the config as `check` does and exit with status 2, printing every problem, when it is invalid, and also when the escrow key hash cannot be resolved (see the escrow spec). Otherwise it SHALL make itself non-dumpable and a child subreaper, start a supervisor for every enabled server (OAuth servers with the grants in the `oauth` directory of the state directory, see the oauth spec), listen on `listen.addr`, and log JSON lines to stderr at `logLevel` and above. When systemd passes it a socket (`LISTEN_FDS` set and `LISTEN_PID` naming the gate's process), it SHALL serve that socket instead of opening `listen.addr`, logging a warning when the socket is on another address; more than one socket, or one that is not a listening TCP socket, SHALL make it exit with status 2. When `NOTIFY_SOCKET` is set it SHALL send `READY=1` there once startup is over (see Health) and `STOPPING=1` when it begins to shut down. SIGHUP reloads the config (see the reload spec). Neither these variables nor the passed socket SHALL reach the stdio servers. On SIGINT or SIGTERM it SHALL stop accepting connections, leaving those that wait on a socket systemd holds to the next process, end the `subscriptions/listen` streams, and for up to 1 second still serve the requests that arrive on open connections, answering each request from then on with `Connection: close`; it SHALL then close the connections that are idle or on which no request has arrived, give calls in flight up to 10 seconds from the start of the shutdown (their progress still delivered), stop every server in parallel, logging one that does not stop within 15 seconds, and exit with status 0; it SHALL exit with status 2 when it cannot listen or the listener fails.

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
