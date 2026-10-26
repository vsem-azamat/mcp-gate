# Configuration

[Docs](../README.md) / **Configuration**

mcp-gate reads one YAML file. The behaviour is specified in [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md); this page is the reference. `mcp-gate check <file>` validates a file (see [check](../commands/check.md)), and `mcp-gate import` writes one from an mcp-proxy `config.json` (see [import](../commands/import.md)).

The schema holds only what this build implements, so an unknown key is an error rather than a setting that is silently ignored. `mcp-gate serve` serves the file (see [serve](../commands/serve.md)); `mcp-gate check -connect` connects to its servers and stops.

## Example

```yaml
version: 1
name: mcp-gate
listen:
  addr: 127.0.0.1:9090
  behindProxy: true
  allowedHosts: [mcp.example.com]
startupGracePeriod: 90s
logLevel: info
auth:
  tokens: {laptop: "${GATE_TOKEN_LAPTOP}", phone: "${GATE_TOKEN_PHONE}"}
admin:
  tokens: {owner: "${GATE_ADMIN_TOKEN}"}
escrow:
  ttl: 24h
  maxEntries: 1000
servers:
  notes:
    stdio:
      command: /usr/bin/node
      args: [server.js]
      cwd: /srv/notes
      env: {NOTES_DB: /srv/notes/db, NOTES_TOKEN: "${NOTES_TOKEN}"}
      inheritEnv: [PATH, HOME, LANG]
    callTimeout: 3m
    tools: {allow: [search, read_note]}
    prompts: {allow: []}
    redact:
      ru: true
      escrowTTL: 1h
      files: {tools: [download_attachment], roots: [/srv/notes/downloads], maxBytes: 20MiB}
    log: {requests: true}
  shop:
    http:
      url: https://shop.example.com/mcp
      headers: {X-Api-Key: "${SHOP_KEY}"}
    callTimeout: 2m
    maxMessageBytes: 8MiB
    protocolVersion: "2025-11-25"
    resources: {deny: ["shop://orders/private"]}
    auth:
      inherit: false
      tokens: {shop-bot: "${GATE_TOKEN_SHOP}"}
    disabled: true
  mail:
    http:
      url: https://mail.example.com/mcp
      oauth: {}              # discovered, client registered at login
  docs:
    http:
      url: https://docs.example.com/mcp
      oauth:
        authServerMetadataURL: https://auth.example.com/.well-known/oauth-authorization-server/tenant
        scopes: [docs.read, offline_access]
```

An `oauth` server needs a grant, which `mcp-gate auth login` obtains (see [auth](../commands/auth.md)).

## Keys

| Key | Default | Meaning |
| --- | --- | --- |
| `version` | required | Always `1` |
| `name` | `mcp-gate` | Client name sent to the servers, and the `name` of `/_healthz` and `/_readyz` |
| `listen.addr` | `127.0.0.1:9090` | `host:port` to serve on |
| `listen.behindProxy` | `false` | The gate sits behind a reverse proxy: the SDK's DNS-rebinding check (a loopback listener only answers loopback Host names) is off, and the request log reads `X-Forwarded-For` from `trustedProxies` |
| `listen.trustedProxies` | `127.0.0.1/32 ::1/128` | CIDRs of the proxies whose `X-Forwarded-For` is believed |
| `listen.allowedHosts` | none (any) | Host names, optionally with a port, the MCP routes answer; others get 403. Set it when `behindProxy` is on; without it the gate logs a warning at start |
| `startupGracePeriod` | `30s` | Longest time `/_readyz` reports `initializing` while servers connect |
| `logLevel` | `info` | `debug`, `info`, `warn` or `error`; `debug` adds the servers' own log messages |
| `auth.tokens` | none | Client tokens by name, accepted by every server that inherits them. The name identifies the caller in the audit log |
| `admin.tokens` | none | Tokens by name that may read `/_status`; without them `/_status` is 404 |
| `escrow.ttl` | `24h` | How long the escrow keeps a secret, unless its server sets `redact.escrowTTL`. The escrow is on only when `MCP_HUB_ESCROW_KEY_SHA256` is set (see [serve](../commands/serve.md#escrow)) |
| `escrow.maxEntries` | `1000` | Most secrets and files kept at once, up to 100000; the oldest is evicted |
| `servers.<name>` | | One downstream server. The name is lower-case letters, digits, `.`, `_` and `-`, up to 63 characters, and becomes the path `/<name>/mcp` |
| `stdio.command` | required | Program to start, without a shell; a name without `/` is looked up in the gate's `PATH` |
| `stdio.args` | none | Its arguments |
| `stdio.cwd` | the gate's | Absolute working directory |
| `stdio.env` | none | Variables set for the child; they win over inherited ones |
| `stdio.inheritEnv` | `PATH HOME LANG LC_* TZ USER XDG_RUNTIME_DIR` | The gate's variables the child inherits; `*` at the end matches a prefix; `[]` inherits nothing |
| `http.url` | required | Streamable HTTP endpoint, `http` or `https`, without user information or fragment |
| `http.headers` | none | Headers sent with every request, such as an API key. Headers mcp-gate sets (`Accept`, `Accept-Encoding`, `Content-Type`, every `Mcp-` header and the like) cannot be set |
| `http.oauth` | none | Authorize the requests with an OAuth grant obtained by [`mcp-gate auth login`](../commands/auth.md). The `url` must then be https, or http on a loopback address, and `headers` cannot set `Authorization`. Every key below is optional |
| `oauth.clientID` | registered at login | A client registered with the authorization server in advance; without it the login registers one dynamically |
| `oauth.clientSecret` | none | The secret of `clientID`, for a confidential client; put it in the environment |
| `oauth.redirectURL` | `http://localhost:8090/oauth/callback` | Where the browser is sent after sign-in; nothing needs to listen there. https, or http on a loopback address |
| `oauth.scopes` | discovered | Scopes to request instead of those the server names |
| `oauth.authServerMetadataURL` | discovered | Where to read the authorization server's metadata, in the RFC 8414 or OpenID Connect well-known form, for a server whose metadata is not found at its issuer |
| `callTimeout` | `0s` | Bound on each request; `0s` is none. While a call runs no probe is sent, so with `0s` a server that stops answering mid-call is not noticed until the call ends |
| `maxMessageBytes` | `16MiB` | Largest stdio frame, HTTP response body or event; a larger response fails only its request. `4KiB` to `1GiB` |
| `protocolVersion` | none | Pin the protocol version offered to the server |
| `probeInterval` | `30s` | Time between liveness probes, at least `1s` |
| `restart.maxBackoff` | `30s` | Longest wait between restarts, `1s` to `5m`; the upper bound keeps an OAuth server's connect attempts within the window in which repeated 401s reject its grant |
| `disabled` | `false` | Never start the server |
| `tools` | all | `{allow: [names]}` or `{deny: [names]}`. An empty allow list exposes every tool, as mcp-proxy's `toolFilter` did |
| `prompts` | all | `{allow: [...]}` or `{deny: [...]}` by prompt name. An empty allow list exposes none and the capability is not advertised |
| `resources` | all | The same, matching a resource's URI or name and a template's URI template or name. Under a deny list, a read of a denied URI through a template is refused too, in any spelling the gate can tell is the same; an allow list is the safer choice |
| `auth.inherit` | `true` | Accept the global `auth.tokens` too |
| `auth.tokens` | none | Tokens this server accepts in addition; with `inherit`, their names differ from the global ones |
| `auth.public` | `false` | Serve without a token. Excludes `tokens` and `inherit` |
| `log.requests` | `false` | Log each HTTP request to the route: method, status, duration, remote address |
| `redact.enabled` | `true` | Redact results; see [Redaction](../architecture/redaction.md) |
| `redact.ru` | `false` | Add the Russian label rules |
| `redact.highEntropy` | `false` | Add the high-entropy rule |
| `redact.disableRules` | none | Redaction kinds never reported, such as `jwt` |
| `redact.escrowTTL` | `escrow.ttl` | How long the escrow keeps this server's secrets |
| `redact.files.tools` | required with `files` | Tools that save a file locally and report its path; the files they write are scanned and withheld when they hold secrets. Needs `redact.enabled` |
| `redact.files.roots` | required with `files` | Absolute directories the tools write to (not `/`, not `$HOME` or a directory above it); only files under them are read, and a path only the arguments name when written during the call; without a usable `$HOME` the check is skipped with a warning |
| `redact.files.maxBytes` | `20MiB` | Largest file scanned, `1KiB` to `1GiB`. A larger text file withholds the whole result; a larger binary file passes |
| `forwardMeta` | none | `_meta` keys of a client request passed to the server, by exact name, such as `example.com/trace`. Others are dropped: they describe the client. `progressToken` and `mcp`/`modelcontextprotocol`-prefixed keys are the gate's and cannot be listed |

Each server has exactly one of `stdio` and `http`. Every server that is not `public` must accept at least one token, and no two tokens a server accepts may have the same value. Token names are lower-case letters, digits, `.`, `_` and `-`; values may not contain spaces or control characters.

## Values

- Durations are strings with a unit: `500ms`, `30s`, `2m`, `1h`. Sizes are strings with a binary unit: `512KiB`, `16MiB`. A bare number is rejected.
- `${NAME}` in any string value is replaced by the environment variable `NAME`; an unset or empty variable is an error. `$$` is a literal `$`; any other `$` is kept. Expansion happens after the YAML is parsed, so a value can never add keys.
- Secrets belong in the environment (for example a systemd `EnvironmentFile=`), referenced with `${NAME}`.

Errors name the field, such as `servers.notes.stdio.cwd: must be an absolute path`, and never print values.
