# import

[Docs](../README.md) / [Commands](README.md) / **import**

`mcp-gate import <config.json>` converts a [TBXark/mcp-proxy](https://github.com/TBXark/mcp-proxy) config into an mcp-gate config and writes it to stdout. The `redact` blocks, the escrow settings and the file-scanning keys below are not part of upstream mcp-proxy; they come from builds that extend it, and the import maps them when a config has them. The mapping is specified in [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md).

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
| `options.reconnectInterval` | `restart.maxBackoff`, lowered to `5m` at most |
| `mcpProxy.addr` | `listen.addr` |
| `mcpProxy.startupGracePeriod` | `startupGracePeriod` |
| `options.authTokens` | named tokens: `auth.tokens`, a server's own `auth.tokens` with `inherit: false`, or `auth.public: true` |
| `options.logEnabled` | `log.requests` |
| `toolFilter`, `promptFilter`, `resourceFilter` | `tools`, `prompts`, `resources`; mode `allow` becomes `allow`, `block` becomes `deny` |
| `options.redact` | `redact`, with `ru: true` (mcp-proxy always ran the Russian rules), `highEntropy`, `disableRules` |
| `mcpProxy.options.redact.escrowTTL`, `escrowMaxEntries` | `escrow.ttl`, `escrow.maxEntries` |
| a server's own `redact.escrowTTL` | `redact.escrowTTL` |
| `redact.fileTools`, `fileRoots`, `fileMaxBytes` | `redact.files.tools`, `roots`, `maxBytes` |
| `oauth` of a streamable HTTP server: `clientId`, `clientSecret`, `redirectUri`, `scopes`, `authServerMetadataUrl` | `http.oauth`: `clientID`, `clientSecret`, `redirectURL`, `scopes`, `authServerMetadataURL` |
| `$VAR`, `${VAR}` | `${VAR}`; any other `$` becomes `$$` |

Options set in `mcpProxy.options` are applied to each server, as mcp-proxy did, except filters there, which mcp-proxy ignored. Keys mcp-proxy ignores, `mcpProxy.version`, `mcpProxy.type: streamable-http`, `mcpProxy.baseURL` without a path, `panicIfInvalid`, `autoReconnect`, a `toolFilter` that allows an empty list (no filter in mcp-proxy) and an empty block list are dropped with a comment.

mcp-proxy passed each request's `_meta` to the server as it was. The import writes no `forwardMeta`, so mcp-gate passes none, and says so in a comment; list keys a server needs by hand.

## Tokens

mcp-proxy tokens are a list; mcp-gate names each token, and the name shows up in the audit log. A token written as `${VAR}` is named after its variable, lower-cased, without the prefix up to the last `_` that every token variable shares: `${HUB_TOKEN_LAPTOP}`, `${HUB_TOKEN_PHONE}` and `${HUB_TOKEN_MAIL}` become `laptop`, `phone` and `mail`. When that does not give distinct valid names, or a token is written in the file (which gives a warning), the tokens are named `token1`, `token2` and so on. Rename them freely; only the values matter to clients.

A server whose `authTokens` are the global ones inherits them. One with its own list gets `auth.inherit: false` and its tokens, since in mcp-proxy its list replaced the global one. One left without any token gets `auth.public: true`.

## Redaction

A server whose effective options have a `redact` block keeps it, with `ru: true`. A server without one gets `redact.enabled: false` and a comment, since mcp-proxy did not redact it; mcp-gate redacts by default, so consider removing that line.

The escrow keys map one to one; the key hash stays in `MCP_HUB_ESCROW_KEY_SHA256`. A server's own `escrowMaxEntries`, which mcp-proxy ignored, is dropped with a warning. File scanning is written only where mcp-proxy did scan: roots that are not absolute paths are dropped, and file tools left without a root, or roots without tools, are dropped with a warning.

mcp-proxy children inherited the whole environment; mcp-gate children get only `inheritEnv` and `env`. A command such as `/usr/bin/env -u SECRET -u HOME MODE=fast server --stdio` is unwrapped: the command becomes `server --stdio`, `MODE=fast` goes to `env`, `HOME` is removed from `inheritEnv`, and `SECRET` is dropped with a comment, since it is not inherited anyway. `-i` gives `inheritEnv: []` and `-C dir` gives `cwd`. A form the importer does not understand is kept as it is, with a note.

## OAuth

An `oauth` block is kept, and each OAuth server needs a login after the import: `mcp-gate auth login <config> <server>` for each (see [auth](../commands/auth.md)). mcp-proxy's tokens are not imported. `pkceDisabled: false` is dropped; `pkceDisabled: true` and any other key in the block are not implemented, since mcp-gate always uses PKCE and an OAuth setting it ignored could change whom the server trusts. A `clientSecret` written in the file gives a warning. An `oauth` block on a stdio server, which mcp-proxy ignored, is dropped with a warning.

## Keys this build does not implement

Every other key that changes behaviour (a `baseURL` with a path, the OAuth keys above, the SSE transport) makes the import fail, listing the keys and writing nothing. `-partial` writes the config anyway and lists each dropped key in a comment marked `NOT IMPLEMENTED IN THIS BUILD`; `mcp-gate check` rejects that file until those comments are removed, which means accepting that the keys are dropped.

Notes go to stderr. Neither they nor errors quote values from the input. Exit status: 0 written, 2 otherwise.
