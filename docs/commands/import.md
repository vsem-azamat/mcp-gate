# import

[Docs](../README.md) / [Commands](README.md) / **import**

`mcp-gate import <config.json>` converts an mcp-proxy config into an mcp-gate config and writes it to stdout. The mapping is specified in [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md).

```sh
mcp-gate import config.json > gate.yaml
mcp-gate check gate.yaml
```

## What it maps

| mcp-proxy | mcp-gate |
| --- | --- |
| `mcpProxy.name` | `name` |
| `command`, `args`, `env` | `stdio` |
| `url`, `headers` with `transportType: streamable-http` | `http` |
| `timeout` | `callTimeout`; none becomes `0s` with a comment |
| `options.disabled` (any letter case) | `disabled` |
| `options.pingInterval` | `probeInterval` |
| `options.reconnectInterval` | `restart.maxBackoff` |
| `$VAR`, `${VAR}` | `${VAR}`; any other `$` becomes `$$` |

Options set in `mcpProxy.options` are applied to each server, as mcp-proxy did. Keys mcp-proxy ignores, `mcpProxy.version`, `mcpProxy.type: streamable-http`, `panicIfInvalid`, `autoReconnect` and a `toolFilter` that allows an empty list (no filter in mcp-proxy) are dropped with a comment.

mcp-proxy children inherited the whole environment; mcp-gate children get only `inheritEnv` and `env`. A command such as `/usr/bin/env -u SECRET -u HOME MODE=fast server --stdio` is unwrapped: the command becomes `server --stdio`, `MODE=fast` goes to `env`, `HOME` is removed from `inheritEnv`, and `SECRET` is dropped with a comment, since it is not inherited anyway. `-i` gives `inheritEnv: []` and `-C dir` gives `cwd`. A form the importer does not understand is kept as it is, with a note.

## Keys this build does not implement

Every other key that changes behaviour (listen address, startup grace period, tokens, filters, call logging, redaction, OAuth, the SSE transport) makes the import fail, listing the keys and writing nothing. `-partial` writes the config anyway and lists each dropped key in a comment marked `NOT IMPLEMENTED IN THIS BUILD`; `mcp-gate check` rejects that file until those comments are removed, which means accepting that the keys are dropped.

Notes go to stderr. Neither they nor errors quote values from the input. Exit status: 0 written, 2 otherwise.
