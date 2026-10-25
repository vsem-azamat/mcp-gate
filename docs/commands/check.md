# check

[Docs](../README.md) / [Commands](README.md) / **check**

`mcp-gate check <file>` loads a config the way the gate will: strict YAML, `${VAR}` expanded from the environment, every key validated. The specifications are [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md) and, for `-connect`, [`openspec/specs/downstream-lifecycle/spec.md`](../../openspec/specs/downstream-lifecycle/spec.md); the keys are in [Configuration](../configuration/README.md).

```console
$ mcp-gate check gate.yaml
gate.yaml: valid, 12 servers (1 disabled)
```

Every problem is listed with its field path; values are never printed:

```console
$ mcp-gate check gate.yaml
mcp-gate check: gate.yaml:
  servers.shop.http.headers.X-Api-Key: environment variable SHOP_KEY is unset or empty
  servers.notes.stdio.cwd: must be an absolute path
```

A file written by `mcp-gate import -partial` is rejected until the keys it marks as not implemented are dealt with.

## Connecting

With `-connect`, check also starts every enabled server at once (stdio children included), waits up to `-timeout` (default 60s) for each, prints what it found and stops them. `-v` logs the supervisors and the children's stderr to stderr.

```console
$ mcp-gate check -connect gate.yaml
gate.yaml: valid, 3 servers (1 disabled)
archive: disabled
notes: ready, protocol 2025-11-25 (pinned automatically: the server did not answer the 2026-07-28 handshake), 4 tools
shop: ready, protocol 2026-07-28, 12 tools
```

Exit status: 0 valid (and, with `-connect`, every enabled server connected); 2 otherwise.
