# Testing

[Docs](../README.md) / [Development](README.md) / **Testing**

`make test` runs every test with the race detector in random order. Tests run in-process and need no network beyond loopback.

## Fake MCP servers

[`internal/testkit`](../../internal/testkit/hub.go) provides `testkit.NewHub`, an `httptest` server that serves fake MCP servers at `/<name>/mcp` over stateless streamable HTTP, built on the official Go SDK. Each fake serves a given catalog of tools, prompts, resources and resource templates; calls, prompt gets and resource reads fail. Per hub, options set:

- a bearer token that every request must carry (others get 401, and the hub counts them);
- the list page size, to exercise pagination;
- the protocol versions the servers negotiate;
- the advertised capabilities, overriding what the SDK infers from the catalog;
- JSON responses instead of event streams.

## Goroutine leaks

Every package with network tests verifies in `TestMain` with [goleak](https://github.com/uber-go/goleak) that no goroutine outlives the tests. Code that makes HTTP requests closes its idle connections when it is done, or the leak check fails.
