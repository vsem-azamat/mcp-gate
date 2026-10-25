# check

[Docs](../README.md) / [Commands](README.md) / **check**

`mcp-gate check <file>` loads a config the way the gate will: strict YAML, `${VAR}` expanded from the environment, every key validated. The specification is [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md); the keys are in [Configuration](../configuration/README.md).

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

Exit status: 0 valid, 2 otherwise.
