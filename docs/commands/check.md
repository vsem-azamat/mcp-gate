# check

[Docs](../README.md) / [Commands](README.md) / **check**

`mcp-gate check <file>` loads a config the way the gate will: strict YAML, `${VAR}` expanded from the environment, every key validated. The specifications are [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md) and, for `-connect`, [`openspec/specs/downstream-lifecycle/spec.md`](../../openspec/specs/downstream-lifecycle/spec.md); the keys are in [Configuration](../configuration/README.md).

```console
$ mcp-gate check gate.yaml
gate.yaml: valid, 12 servers (1 disabled)
escrow: on, key hash from MCP_GATE_ESCROW_KEY_SHA256
```

The second line says whether the [escrow](serve.md#escrow) would be on and where its key hash comes from (`escrow.keyHash`, `escrow.keyHashFile`, `MCP_GATE_ESCROW_KEY_SHA256`, or the deprecated `MCP_HUB_ESCROW_KEY_SHA256`), never the hash itself. A key hash file is read as `serve` reads it, with the same checks on its owner, so run `check` as the gate's user or as root (see [systemd](../operations/systemd.md#commands-in-the-services-environment)); a hash that is invalid or that disagrees with another source fails the check.

Every problem is listed with its field path; values are never printed:

```console
$ mcp-gate check gate.yaml
mcp-gate check: gate.yaml:
  servers.shop.http.headers.X-Api-Key: environment variable SHOP_KEY is unset or empty
  servers.notes.stdio.cwd: must be an absolute path
```

A file written by `mcp-gate import -partial` is rejected until the keys it marks as not implemented are dealt with.

## Connecting

With `-connect`, check also starts every enabled server at once (stdio children included), waits up to `-timeout` (default 60s) for each, prints what it found and stops them. `-v` logs the supervisors and the children's stderr to stderr. OAuth servers use the grants in `-state-dir` (default `$STATE_DIRECTORY`), as `serve` does, and may refresh them; one without a grant is reported with the login command:

```console
$ mcp-gate check -connect -state-dir /var/lib/mcp-gate gate.yaml
mail: OAuth login required (not logged in): run mcp-gate auth login <config> mail
```

```console
$ mcp-gate check -connect gate.yaml
gate.yaml: valid, 3 servers (1 disabled)
escrow: off (no key hash in escrow.keyHash, escrow.keyHashFile, MCP_GATE_ESCROW_KEY_SHA256 or MCP_HUB_ESCROW_KEY_SHA256)
archive: disabled
notes: ready, protocol 2025-11-25 (pinned automatically: the server did not answer the 2026-07-28 handshake), 4 tools
shop: ready, protocol 2026-07-28, 12 tools
```

Exit status: 0 valid (and, with `-connect`, every enabled server connected); 2 otherwise.
