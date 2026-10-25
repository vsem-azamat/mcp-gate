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

## Goroutine leaks

Every package with network tests verifies in `TestMain` with [goleak](https://github.com/uber-go/goleak) that no goroutine outlives the tests. Code that makes HTTP requests closes its idle connections when it is done, or the leak check fails.

## Fuzzing

Fuzz targets (`Fuzz*` functions) check invariants on arbitrary input; the redaction engine and its MCP adapter have them. `make test` runs only their seed corpora. `make fuzz` runs each target for `FUZZTIME` (default `60s`), for example `make fuzz FUZZTIME=10m`. A failing input is saved under the package's `testdata/fuzz/` and runs as a regular test from then on; commit it with the fix.

## Benchmarks

`make bench` runs every benchmark with allocation counts. Benchmarks have no time budget in CI; compare runs before and after a change, for example with `go test -run '^$' -bench . -count 10 ./internal/redact/...`.
