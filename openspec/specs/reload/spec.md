# reload Specification

## Purpose

On SIGHUP, `mcp-gate serve` applies a changed config without a restart: as a whole and at one instant, so that no request sees part of one config and part of another, restarting only the servers whose downstream settings changed and keeping the routes, and their listening clients, whose inputs did not.

## Requirements

### Requirement: Reload

On SIGHUP `serve` SHALL load its config file again, with the environment it started with, resolve the escrow key hash as at the start, and apply the config without a restart; SIGHUP SHALL be caught before the config is first loaded, and one that arrives before the servers were started SHALL be applied once they are. With `NOTIFY_SOCKET` set, once startup is over (see Health in the gate-lifecycle spec), it SHALL send `RELOADING=1` with `MONOTONIC_USEC` when a reload begins and `READY=1` when it is over, whether or not the config was applied; a reload during startup SHALL send neither, one after the shutdown began SHALL be skipped, and nothing SHALL be sent after `STOPPING=1`. A config that does not load or pass validation SHALL be rejected with an error line, and the gate SHALL go on with the config it has; `check` SHALL accept exactly the configs a reload applies.

A valid config SHALL be applied as a whole, at one instant: every request that arrives from then on SHALL be served under the new config, and a request in flight SHALL finish under the config it arrived under, its tokens, filters, redaction and request logging, so that no request sees part of one config and part of another. A request whose token was checked before the reload but whose body was still arriving, or that was held (see Routes in the routes-and-auth spec), when the reload replaced its route SHALL be served under the new config, its token checked again and nothing of the old check kept. What a change of each config key does SHALL be one of:

- **Restart of the server**: the server's `stdio` or `http` with every key under them, `callTimeout`, `maxMessageBytes`, `protocolVersion`, `probeInterval`, `restart` and `disabled`, and the config's `name`, which servers get as the client name. The server SHALL be stopped once the requests in flight on the routes that reach it, under this or an earlier config, have ended, at most 10 seconds after the reload, and then started with the new settings; a removed or disabled server SHALL be stopped the same way. When the shutdown begins first, the servers SHALL be stopped by it, after its own grace for calls in flight. A server that is new SHALL start only after those stops, and the replacement of a server whose old process did not end within 15 seconds SHALL start only once it has, so that two processes of a stdio server never run together. Meanwhile the server's catalog stays listed, and requests to it SHALL be held until it is up, at most `startupGracePeriod`, as during startup.
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
