# Testing

[Docs](../README.md) / [Development](README.md) / **Testing**

`make test` runs every test with the race detector in random order. Tests run in-process and need no network beyond loopback. Timing tests skip under `-short` and use smaller inputs under the race detector.

## Fake MCP servers

[`internal/testkit`](../../internal/testkit/hub.go) provides `testkit.NewHub`, an `httptest` server that serves fake MCP servers at `/<name>/mcp` over stateless streamable HTTP, built on the official Go SDK. Each fake serves a given catalog of tools, prompts, resources and resource templates; calls, prompt gets and resource reads fail. Per hub, options set:

- a bearer token that every request must carry (others get 401, and the hub counts them);
- the list page size, to exercise pagination;
- the protocol versions the servers negotiate;
- the advertised capabilities, overriding what the SDK infers from the catalog;
- JSON responses instead of event streams.

## Scriptable fakes

[`internal/testkit/fake.go`](../../internal/testkit/fake.go) describes a fake server with `testkit.Fake` and serves it two ways:

- `testkit.StdioCommand` returns a command that re-executes the test binary as a stdio MCP server. A package that uses it calls `testkit.RunFake()` first in `TestMain`, which runs the fake and exits when the binary was started that way.
- `testkit.NewFakeHTTP` serves it over stateless streamable HTTP, optionally with JSON responses or gzip, and `SetDown` makes it answer 503.

Every fake has the tools `echo`, `sleep`, `big` (a result of a given size), `hang`, `crash` (the stdio fake exits), `env`, `pids`, `stats` (pings during calls, cancelled calls), `progress` (progress notifications of a given count and size), `meta` (the request's `_meta`), `addtool` (a list change), `badblob` (a result redaction must withhold) and `writefile` (a download tool that writes a file and reports its path). Options narrow the protocol versions, leave `server/discover` unanswered (a legacy server), reject `subscriptions/listen`, handle one request at a time, stop answering after a while, refuse probes with an error reply, serve a prompt, resources and templates, and for stdio exit at start, ignore SIGTERM, start a grandchild in the process group, or write to stderr and stdout.

[`testkit.NewOAuthServer`](../../internal/testkit/oauth.go) serves a fake behind OAuth on one loopback listener: protected resource metadata, an authorization server with dynamic registration, PKCE checks and refresh tokens, and the MCP endpoint, which answers 401 with a challenge to any token it did not issue. `Approve` plays the user who signs in and returns the address the browser would be sent to, and `Login` runs a whole login into a store. Options leave out the challenge, the resource metadata or registration, put the issuer under a path, rotate refresh tokens, send `iss`, issue no refresh token or claim another issuer; `ExpireAccess` and `RevokeAll` void the tokens issued so far.

`internal/downstream` runs the downstream half of the version matrix with them: every protocol version the SDK supports, over stdio, HTTP with event streams and HTTP with JSON. `internal/gate` runs the whole matrix through a running gate: clients of each version against servers of each version, over stdio and HTTP. Its tests start a gate on a loopback port with stdio and HTTP fakes behind it, and `TestCompareWithHub` checks with `compare` that the gate serves the catalog of a fake hub unchanged. `internal/procutil` re-executes its test binary the same way, with its own helper modes.

## Escrow contract

[`testkit.CheckEscrowContract`](../../internal/testkit/escrow.go) checks the escrow HTTP contract against a base URL holding one live entry: the auth scheme, the paths, methods, status codes, bodies and headers, and the meta document's members in order. `internal/escrow` runs it against the bare handler and `internal/gate` against a running gate, with the entry planted by a tool call.

## Goroutine leaks

Every package with network tests verifies in `TestMain` with [goleak](https://github.com/uber-go/goleak) that no goroutine outlives the tests. Code that makes HTTP requests closes its idle connections when it is done, or the leak check fails.

## Fuzzing

Fuzz targets (`Fuzz*` functions) check invariants on arbitrary input; the redaction engine and its MCP adapter have them. `make test` runs only their seed corpora. `make fuzz` runs each target for `FUZZTIME` (default `60s`), for example `make fuzz FUZZTIME=10m`. A failing input is saved under the package's `testdata/fuzz/` and runs as a regular test from then on; commit it with the fix.

## Benchmarks

`make bench` runs every benchmark with allocation counts. Benchmarks have no time budget in CI; compare runs before and after a change, for example with `go test -run '^$' -bench . -count 10 ./internal/redact/...`.
