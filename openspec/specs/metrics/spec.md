# metrics Specification

## Purpose

`mcp-gate serve` counts what it does — requests by server, entry, token and outcome, their durations, redactions, downstream restarts and states, the escrow's entries, reloads and failed authentication — and serves the counts in the Prometheus text exposition format at `/_metrics`. The counts are taken from the audit records of the requests (see the serving spec) and from hooks in the supervisors, the escrow, the token checks and reloads, never from a second record of the same events.

## Requirements

### Requirement: Metrics endpoint

With `metrics.enabled` set, `GET /_metrics` on the listener SHALL return, to a request carrying an `admin.tokens` token as `/_status` takes it, the metrics in the Prometheus text exposition format version 0.0.4 (`Content-Type: text/plain; version=0.0.4; charset=utf-8`); others SHALL get 401. `metrics.enabled` SHALL need `admin.tokens`. Without `metrics.enabled` the path SHALL be 404. With `metrics.addr` set, the gate SHALL also listen on that address, which SHALL be a loopback address or `localhost`, and serve there `GET /_metrics` without a token and nothing else (404), for a scraper on the same host; since it takes no token, every local user and process can read it, the MCP clients and the stdio servers on the host included. It SHALL answer 403 to a request whose Host is not `localhost` or a loopback address (with any port or none), so that a web page whose name resolves to the loopback address cannot read it (DNS rebinding); that listener SHALL have the main listener's limits, SHALL open when the servers start, and a failure to open it SHALL stop the start. Every answer SHALL carry `Cache-Control: no-store`. The endpoint is off by default, since it names servers, tools and tokens. The counting SHALL run whether or not the metrics are served, so that a reload that turns the endpoint on serves the counts since the start.

#### Scenario: Endpoint guarded like status

- **WHEN** `metrics.enabled` is set and a client reads `/_metrics` with an admin token, with a client token, and without a token
- **THEN** the first gets 200 with the exposition format and `Cache-Control: no-store`, the others 401

#### Scenario: Endpoint off

- **WHEN** `metrics.enabled` is not set
- **THEN** `/_metrics` is 404

#### Scenario: Separate loopback listener

- **WHEN** `metrics.addr` is a loopback address
- **THEN** `/_metrics` on it answers 200 without a token and any other path 404

#### Scenario: Rebound Host on the loopback listener

- **WHEN** a request to `metrics.addr` carries `Host: evil.example.com:9464`
- **THEN** it gets 403, and one with `Host: localhost:9464`, `127.0.0.1` or `[::1]` gets 200

### Requirement: Metric families

The gate SHALL serve these families, each with `# HELP` and `# TYPE` lines, families and series in a fixed order:

- `mcp_gate_build_info{version}`, a gauge of 1.
- `mcp_gate_requests_total{server,kind,name,token,outcome}`, a counter of the audit records: `kind` is `tool`, `prompt` or `resource`, `token` the record's principal (the token's name, never its value; empty without a token), `outcome` the record's outcome, and `server` empty for a request the aggregate refused before any server saw it.
- `mcp_gate_request_duration_seconds{server,kind,name}`, a histogram of the records' durations with the upper bounds 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120 and 300 seconds.
- `mcp_gate_redactions_total{server}`, a counter of the findings replaced and the files withheld in results.
- `mcp_gate_downstream_restarts_total{server}`, a counter of the supervisors' connection attempts after the first (as `restarts` in `/_status`).
- `mcp_gate_downstream_state{server,state}`, a gauge, for each enabled server and each supervisor state (`starting`, `ready`, `degraded`, `backoff`, `disabled`, `stopped`, `needs-login`), of 1 for the state it is in and 0 for the others.
- `mcp_gate_escrow_entries`, a gauge of the entries the escrow holds, and `mcp_gate_escrow_stored_total`, a counter of the entries it stored under a new handle; both only with the escrow on.
- `mcp_gate_reloads_total{result}`, a counter of reloads by `success` or `failure`: a config that did not load or could not be applied is a failure; a reload skipped because the shutdown began is not counted.
- `mcp_gate_auth_failures_total{route}`, a counter of the requests answered with 401 because they carried no accepted token, by route: `/<server>/mcp`, `/mcp`, `/_status`, `/_metrics` and `/_escrow/`.

Label values SHALL be escaped as the format requires. Counters and histograms SHALL keep their series for the life of the process, including those of servers a reload removed, and SHALL NOT be reset by a reload.

#### Scenario: Counting a call

- **WHEN** a client with the token `laptop` calls the tool `echo` of `server-a` and the result has a secret redacted
- **THEN** `mcp_gate_requests_total{server="server-a",kind="tool",name="echo",token="laptop",outcome="ok"}` is 1, the duration histogram of the tool has one observation, and `mcp_gate_redactions_total{server="server-a"}` is 1

#### Scenario: Restarts, states and auth failures

- **WHEN** a stdio server exits and is restarted, and a request to its route carries a wrong token
- **THEN** `mcp_gate_downstream_restarts_total` of the server is at least 1, its `mcp_gate_downstream_state` is 1 for exactly one state, and `mcp_gate_auth_failures_total{route="/<server>/mcp"}` is 1

#### Scenario: Counters survive a reload

- **WHEN** calls were counted and a reload changes a server's filters and then a reload fails
- **THEN** the counts of the calls are unchanged and `mcp_gate_reloads_total` is 1 for `success` and 1 for `failure`

### Requirement: Bounded labels

Label values SHALL come only from the config and from the servers' catalogs, never from what a client sends. `name` SHALL be the tool or prompt name, as the audit line gives it, only when the entry was in the server's mirrored catalog when the request ended and the caller's token policy does not hide it, and only for the first 100 distinct names of a server and kind; any other tool or prompt SHALL be counted under `name="(other)"`. A resource read SHALL be counted with an empty `name`, since URIs are unbounded.

#### Scenario: Unknown tool

- **WHEN** a client calls a tool that the server does not list
- **THEN** the call is counted with `name="(other)"` and outcome `denied`, and the name it sent appears nowhere in `/_metrics`

#### Scenario: Tool hidden by a token policy

- **WHEN** the token `phone`, whose policy hides the listed tool `big`, calls it
- **THEN** the call is counted with `name="(other)"`, as a tool the server does not have, and `name="big"` appears nowhere in `/_metrics`, so the metrics do not tell a hidden entry from a missing one
