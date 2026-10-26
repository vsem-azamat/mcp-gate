# routes-and-auth Specification

## Purpose

Each enabled server is served at `/<name>/mcp` over stateless streamable HTTP, through one chain of checks: the Host, a named bearer token, cross-origin protection, the hold while the server connects, and the body limit. Tokens are named, and the name identifies the caller in the audit lines.

## Requirements

### Requirement: Routes

Each enabled server SHALL be served at exactly `/<name>/mcp`; any other path, including the route of a disabled server, SHALL get 404, except `/mcp` when the aggregate endpoint is on (see the aggregate-endpoint spec), `/_healthz`, `/_readyz`, `/_status` and, with the escrow on and `escrow.tcp` true, the escrow API under `/_escrow/`, which none of the route checks below apply to. A route SHALL run, in this order: the Host check, the token check, cross-origin protection, a 503 with `Retry-After: 5` while the server's catalog has never been listed, a request body limit of 4 MiB (413) read within 30 seconds (408), and the SDK's stateless streamable HTTP handler, which answers GET with 405. Until startup is over (see Health in the gate-lifecycle spec), a request to a server whose catalog has never been listed and that is not in `needs-login` SHALL be held until the catalog is listed, the server is in `needs-login`, or startup ends, and only then answered or refused with the 503, which a held request SHALL get at once when the shutdown begins, so that a client of a gate that has just started is not refused while the server connects. Sessions SHALL survive a restart of the gate: the handler keeps no session, so a client that initialized with one gate process SHALL go on calling another without initializing again. A POST holding one JSON-RPC call SHALL be answered with `application/json` when its client accepts `application/json`, it is not `subscriptions/listen`, and its params carry no `_meta.progressToken` unless the client accepts only `application/json`; a batch, a `subscriptions/listen` request and a request with a progress token SHALL be answered with a `text/event-stream`, as SHALL a request whose client accepts `text/event-stream` but not `application/json`. A client that accepts only one of the two types (counting `*/*`, `application/*` and `text/*`, and not a type given `q=0`, which a wildcard does not override) SHALL get that one, a request with a progress token then losing its progress when it is `application/json`; `subscriptions/listen` without `text/event-stream`, and any request accepting neither, SHALL get 400. Notifications and responses from the client SHALL get 202 with no body. When `listen.allowedHosts` is set, a request whose Host is not in it (an entry without a port matching any port, without regard to case) SHALL get 403. Unless `listen.behindProxy` is set, the SDK's DNS-rebinding check SHALL reject a request to a loopback listener whose Host is not a loopback name. A panic in an HTTP handler SHALL be answered with 500, and a panic while handling an MCP request or a notification with an internal JSON-RPC error or nothing; either SHALL be logged by its type, without its value. The listener SHALL bound request headers to 64 KiB read within 10 seconds and close idle connections after 120 seconds, and SHALL NOT bound the time a call takes. Each write of a response, of at most 64 KiB, SHALL fail when it has not completed within 30 seconds; the connection is then closed and the request's context cancelled, which cancels its call, so a client that stops reading cannot hold the gate's resources while the connection stays up. This holds for the escrow API and the socket as well.

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
