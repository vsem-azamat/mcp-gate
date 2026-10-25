# compare

[Docs](../README.md) / [Commands](README.md) / **compare**

`mcp-gate compare` lists the tools, prompts, resources and resource templates of MCP servers on two sources and prints every difference. It only lists: it never calls a tool, gets a prompt or reads a resource. It needs no mcp-gate configuration. The specification is [`openspec/specs/compare/spec.md`](../../openspec/specs/compare/spec.md).

## Sources

A source (`-a`, `-b`) is either an endpoint URL template or a snapshot file.

- An endpoint template contains `{server}` in its path, which is replaced by each server name: `https://mcp.example.com/{server}/mcp`. It may not contain user information or a query string, so a server name can never change the host a token goes to.
- A snapshot is a JSON file written by `-snapshot`.

Flags go before the server names; each server may be named once.

Tokens come from environment variables named by `-a-token-env` and `-b-token-env` and are sent as `Authorization: Bearer <token>`, each only to its own source. Redirects are not followed.

## Examples

Two gateways, one token each:

```sh
export OLD_TOKEN=... NEW_TOKEN=...
mcp-gate compare \
  -a 'https://old.example.com/{server}/mcp' -a-token-env OLD_TOKEN \
  -b 'http://127.0.0.1:9090/{server}/mcp' -b-token-env NEW_TOKEN \
  server-a server-b
```

Save a snapshot now, compare against it later (without server names, every server in the snapshot is compared):

```sh
mcp-gate compare -a 'https://old.example.com/{server}/mcp' -a-token-env OLD_TOKEN -snapshot old.json server-a server-b
mcp-gate compare -a old.json -b 'http://127.0.0.1:9090/{server}/mcp' -b-token-env NEW_TOKEN
```

## Output

A server without differences prints one line:

```text
server-a: identical (3 tools, 0 prompts, 1 resource, 0 resource templates)
```

Each difference is a line naming the server and the entry, with both canonical values for a changed field:

```text
server-a: tool "search": inputSchema differs
  a: {"properties":{"q":{"type":"string"}},"type":"object"}
  b: {"type":"object"}
server-a: resource "notes://index": only in a
```

Read failures go to stderr. Exit status: 0 no differences, 1 differences, 2 usage error or a server that could not be read. `-timeout` (default 30s) bounds reading one server from one source; after a failed read, closing the session with a server that keeps sessions may take up to 5 s more (the SDK's best-effort session `DELETE`).

## Notes

- Entries are compared after the Go SDK decodes them, so a field the SDK does not know is not seen, and a value the SDK normalises compares equal: an absent `readOnlyHint` and `false`, or the schema numbers `10` and `10.0` (decoded as 64-bit floats, so integers beyond 2^53 lose precision).
- The SDK silently drops tools it considers invalid (such as tools with invalid `x-mcp-header` annotations) from `tools/list`; such a tool shows up as missing.
- A list whose capability the server does not advertise counts as empty. The `resources` capability covers both resources and resource templates.
