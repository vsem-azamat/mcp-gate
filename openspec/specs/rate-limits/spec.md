# rate-limits Specification

## Purpose

`limits` caps how often, and how many at once, tool calls, prompt gets and resource reads reach the servers: per token, per server, per tool, or any combination of them. A call over a limit is refused before it is forwarded, with an error that says the limit and when to retry, and an audit line with outcome `limited`.

## Requirements

### Requirement: Limits

The config MAY set `limits`, a list of entries, each with the selectors `token` (a token name as the servers know it, as under `policies`), `server` (a server in `servers`) and `tool` (a tool's own name on that server, without the `<server>__` prefix of `/mcp`; it SHALL need `server`), any of which MAY be left out, and at least one of `rate` and `concurrency`. `rate` SHALL be `<n>/<period>`: a positive whole number of calls and a period that is `s`, `m`, `h` or a positive duration such as `30s`. `burst` (default: the `rate`'s number of calls) is the most calls the entry passes at once after a quiet spell; it SHALL be positive and SHALL need `rate`. `concurrency` is the most calls the entry lets be in flight at once; it SHALL be positive. `token` SHALL be a token in `auth.tokens` or in some server's `auth.tokens`, and with `server` the server SHALL accept it; `tool` SHALL NOT be empty, have surrounding space or start with the server's name and `__`; and no two entries SHALL be the same. Each of these errors SHALL name the entry's field, such as `limits[2].server`.

An entry SHALL match a request whose token has the entry's `token` name, to the entry's `server`, and, with `tool`, only a tool call of that tool; a selector left out SHALL match anything, so an entry without `tool` matches tool calls, prompt gets and resource reads alike, and an entry with `token` matches no request on a public server. Each entry SHALL count, in one bucket of its own, every request it matches, whatever token or server it comes from: a token bucket of `burst` calls that refills at the `rate`, and a count of the calls in flight. A request SHALL pass only when every entry that matches it passes; then it SHALL take one call from each such entry's bucket and hold one of its in-flight places until it ends, and a refused request SHALL take nothing. The check SHALL run after the server's filter and the caller's token policy, so that a request for an entry they hide fails exactly as one for an entry the server does not have, whatever the limits, and a request the SDK refuses before a handler is never counted. It SHALL apply alike on the server's route and on the aggregate endpoint, under the server's own tool names.

A refused request SHALL fail with a JSON-RPC error of code `-32029` whose message starts with `mcp-gate: ` and says the limit of the first matching entry, in the order of `limits`, that refused it: for `rate`, its number of calls and its period and the whole seconds after which it would pass (at least 1); for `concurrency`, its number of calls in flight. A rate refusal SHALL carry `retryAfterMs`, the milliseconds after which that entry would pass, in the error's data. The message SHALL NOT name a token, another entry or anything hidden from the caller. The request SHALL be logged with outcome `limited`, which counts as a failed call, and counted under that outcome in the metrics.

The buckets SHALL live in memory, and a reload SHALL apply a changed `limits` in place, without replacing any mirror or route: an entry that is the same in the new config, all its keys equal, SHALL keep its bucket and its calls in flight, and any other entry SHALL start with a full bucket and nothing in flight.

#### Scenario: Rate per token and tool

- **WHEN** `limits` holds `{token: phone, server: server-a, tool: echo, rate: 2/m}` and `phone` calls `echo` on `server-a` three times within a second
- **THEN** the first two calls succeed, the third fails with code `-32029`, a message saying 2 calls per 1m and a retry after about 30 seconds, and `retryAfterMs` in its data, is logged with outcome `limited` and is not forwarded, while `laptop` and `phone`'s calls of other tools pass

#### Scenario: Every matching limit must pass

- **WHEN** `limits` holds `{server: server-a, rate: 10/s}` and `{token: phone, rate: 1/h}`, and `phone` makes a call to `server-a` and then a second one
- **THEN** the second call is refused by the token's entry, and the server's entry has taken one call only, for the first

#### Scenario: Concurrency

- **WHEN** `limits` holds `{server: server-a, concurrency: 1}` and a call to `server-a` is in flight
- **THEN** a second call fails with a message saying at most 1 call in flight, without `retryAfterMs`, and once the first has ended a call passes

#### Scenario: Hidden tool over a limit

- **WHEN** `phone`'s token policy hides `env` on `server-a` and `limits` holds `{token: phone, rate: 1/h}`, already used up
- **THEN** `phone`'s call of `env` fails exactly as one of a tool the server does not have, with outcome `denied`, not `limited`

#### Scenario: Limits across a reload

- **WHEN** a token has used up `{token: phone, rate: 1/h}` and a reload changes only another entry, and then a reload changes the entry to `rate: 2/h`
- **THEN** after the first reload the token is still refused, and after the second its next call passes

#### Scenario: Invalid limits

- **WHEN** an entry sets `tool` without `server`, `burst` without `rate`, neither `rate` nor `concurrency`, `rate: 0/m`, or a `token` that no server accepts
- **THEN** loading fails naming the field of the entry, such as `limits[0].tool`
