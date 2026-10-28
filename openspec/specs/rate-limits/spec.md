# rate-limits Specification

## Purpose

`limits` caps how often, and how many at once, tool calls, prompt gets and resource reads reach the servers: per token, per server, per tool, or any combination of them. A call over a limit is refused before it is forwarded, with an error that says the limit and when to retry, and an audit line with outcome `limited`.

## Requirements

### Requirement: Limits

The config MAY set `limits`, a list of entries, each with the selectors `token` (a token name as the servers know it, as under `policies`), `server` (a server in `servers`) and `tool` (a tool's own name on that server, without the `<server>__` prefix of `/mcp`; it SHALL need `server`), any of which MAY be left out, and at least one of `rate` and `concurrency`. `rate` SHALL be `<n>/<period>`: a positive whole number of calls and a period that is `s`, `m`, `h` or a positive duration such as `30s`. `burst` (default: the `rate`'s number of calls) is the most calls the entry passes at once after a quiet spell; it SHALL be positive and SHALL need `rate`. `concurrency` is the most calls the entry lets be in flight at once; it SHALL be positive. A selector written empty SHALL count as left out. `token` SHALL be a token some server accepts, and with `server` that server SHALL accept it; `tool` SHALL NOT have surrounding space or start with the server's name and `__`; and no two entries SHALL be the same once their rates are read, so `60/m` and `60/1m` with `burst: 60` are the same entry. Each of these errors SHALL name the entry's field, such as `limits[2].server`.

An entry SHALL match a request whose token has the entry's `token` name, to the entry's `server`, and, with `tool`, only a tool call of that tool; a selector left out SHALL match anything, so an entry without `tool` matches tool calls, prompt gets and resource reads alike, and an entry with `token` matches no request on a public server. Each entry SHALL count, in one bucket of its own, every request it matches, whatever token or server it comes from: a token bucket of `burst` calls that refills at the `rate`, never above `burst`, and a count of the calls in flight, the calls the gate is still waiting on: a call stops being in flight when the server answers or when the gate stops waiting for it, such as when the client cancels it or `callTimeout` passes, even if the server is still working on it. An entry shared by several tokens SHALL let each of them use up the entry for all, so a token can tell from its refusals how much the others use. A request SHALL pass only when every entry that matches it passes; then it SHALL take one call from each such entry's bucket and hold one of its in-flight places until it ends, and a refused request SHALL take nothing. For a tool call or a prompt get the check SHALL run after the server's filter, the tool pins and the caller's token policy, so that a call of a hidden or held entry fails exactly as one of an entry the server does not have, whatever the limits, and is never counted. For a resource read it SHALL run before them, so that a read of a URI they hide takes a call like a read of any other URI that reaches the gate, and is refused by a used-up limit as that one is. A request the SDK refuses before a handler SHALL never be counted. It SHALL apply alike on the server's route and on the aggregate endpoint, under the server's own tool names.

A refused request SHALL fail with a JSON-RPC error of code `-32029` whose message starts with `mcp-gate: ` and says the limit that refused it: of the entries that refused it, the one with `rate` whose wait is longest, or, when only `concurrency` refused, the first of those in the order of `limits`. For `rate` the message SHALL give its number of calls, its period and the whole seconds, rounded up and at least 1, after which that entry would pass, and the error's data SHALL carry `retryAfterMs`, the same wait in milliseconds rounded up; for `concurrency` it SHALL give its number of calls in flight, and there is no data. The message SHALL NOT name a token, another entry or anything hidden from the caller. The request SHALL be logged with outcome `limited`, which counts as a failed call, and counted under that outcome in the metrics.

The buckets SHALL live in memory, and a reload SHALL apply a changed `limits` in place, without replacing any mirror or route: an entry that is the same in the new config, all its keys equal, SHALL keep its bucket and its calls in flight; an entry whose `token`, `server` and `tool` are those of an entry that is not kept SHALL take that entry's calls in flight, and its bucket as it is, capped at the new `burst`, or full when the old entry had no `rate`; and any other entry SHALL start with a full bucket and nothing in flight.

#### Scenario: Rate per token and tool

- **WHEN** `limits` holds `{token: phone, server: server-a, tool: echo, rate: 2/m}` and `phone` calls `echo` on `server-a` three times within a second
- **THEN** the first two calls succeed, the third fails with code `-32029`, a message saying 2 calls per 1m and a retry after about 30 seconds, and `retryAfterMs` in its data, is logged with outcome `limited` and is not forwarded, while `laptop` and `phone`'s calls of other tools pass

#### Scenario: Every matching limit must pass

- **WHEN** `limits` holds `{server: server-a, rate: 10/s}` and `{token: phone, rate: 1/h}`, and `phone` makes a call to `server-a` and then a second one
- **THEN** the second call is refused by the token's entry, and the server's entry has taken one call only, for the first

#### Scenario: Tool entry and a prompt of the same name

- **WHEN** `limits` holds `{server: server-a, tool: greet, rate: 1/h}` and a client gets the prompt `greet` of `server-a` twice
- **THEN** both gets pass

#### Scenario: Concurrency

- **WHEN** `limits` holds `{server: server-a, concurrency: 1}` and a call to `server-a` is in flight
- **THEN** a second call fails with a message saying at most 1 call in flight, without `retryAfterMs`, and once the first has ended a call passes

#### Scenario: Hidden tool over a limit

- **WHEN** `phone`'s token policy hides `env` on `server-a` and `limits` holds `{token: phone, rate: 1/h}`, already used up
- **THEN** `phone`'s call of `env` fails exactly as one of a tool the server does not have, with outcome `denied`, not `limited`

#### Scenario: Limits across a reload

- **WHEN** a token has used up `{token: phone, rate: 1/h}` and a reload changes only another entry, and then a reload changes the entry to `rate: 2/h`, and then one adds `{token: phone, server: server-a, rate: 1/h}`
- **THEN** the token is still refused after the first and the second reload, the second keeping its used-up bucket, and the new entry starts full

#### Scenario: Hidden resource over a limit

- **WHEN** `phone`'s policy on `server-a` denies `fake://hidden`, which a template `phone` sees also matches, and `limits` holds `{token: phone, server: server-a, rate: 1/h}`
- **THEN** `phone`'s read of `fake://hidden` fails as one of an unknown resource and takes the call, and its next reads, of `fake://hidden` or of any other URI, all fail with code `-32029`

#### Scenario: Concurrency place of a cancelled call

- **WHEN** `limits` holds `{server: server-a, concurrency: 1}` and the client cancels a call in flight to `server-a`
- **THEN** a next call to `server-a` passes the limit once the gate has stopped waiting for the cancelled one, without waiting for the server

#### Scenario: Invalid limits

- **WHEN** an entry sets `tool` without `server`, `burst` without `rate`, neither `rate` nor `concurrency`, `rate: 0/m`, a `token` that no server accepts, or two entries that are the same once their rates are read
- **THEN** loading fails naming the field of the entry, such as `limits[0].tool`
