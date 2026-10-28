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
  sourceArguments: [chat_id, message_id, ticket]
  socket: {path: /run/mcp-gate/escrow.sock, allowUIDs: [1001]}   # user 1001 needs no key
aggregate:
  servers: [notes, mail]   # leave out to serve every enabled server
policies:
  phone:                   # a token name
    servers:
      notes: {tools: {allow: [search]}, resources: none}
      mail: {tools: {deny: [send_message, delete_message]}}
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
    redact: {escrow: false, arguments: block}  # plain markers, nothing kept; refuse secrets in arguments
    auth:
      inherit: false
      tokens: {shop-bot: "${GATE_TOKEN_SHOP}"}
    disabled: true
  mail:
    http:
      url: https://mail.example.com/mcp
      oauth: {}              # discovered, client registered at login
    redact:
      substitute:            # escrow handles the agent passes here get their values
        - {tool: login_imap, argument: auth.password, from: {notes: [password]}}
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
| `admin.tokens` | none | Tokens by name that may read `/_status`, and `/_metrics` with `metrics.enabled`; without them `/_status` is 404 |
| `metrics.enabled` | `false` | Serve Prometheus metrics at `/_metrics` on `listen.addr` to `admin.tokens` tokens; needs `admin.tokens` (see [Metrics](../operations/metrics.md)) |
| `metrics.addr` | none | A loopback `host:port` (or `localhost:port`), other than `listen.addr`, that serves only `/_metrics`, without a token, for a scraper on the same host: every local user and process can read it. Requests whose Host is not a loopback name get 403. Read at start |
| `escrow.keyHash` | none | Hex SHA-256 of the escrow API key, as `${VAR}`. Setting `MCP_GATE_ESCROW_KEY_SHA256` in the environment instead needs no config; a variable named here is kept from the stdio servers too. The escrow is on when a key hash comes from here, `escrow.keyHashFile` or the environment (see [serve](../commands/serve.md#escrow)) |
| `escrow.keyHashFile` | none | Absolute path of a file that holds the hex SHA-256, such as a systemd credential (`${CREDENTIALS_DIRECTORY}/escrow-key-sha256`) or a mounted secret. Read at start; it must be a regular file owned by root or the gate's user (any owner when the gate runs as root) and not writable by group or others. Excludes `keyHash` |
| `escrow.ttl` | `24h` | How long the escrow keeps a secret, unless its server sets `redact.escrowTTL` |
| `escrow.maxEntries` | `1000` | Most secrets and files kept at once, up to 100000; the oldest is evicted |
| `escrow.sourceArguments` | `chat_id message_id message_ids topic_id reply_to space space_name message_name thread_name attachment_name conversation_id conversationId channel_id chat peer messageId threadId account` | Call arguments copied into an entry's `source` in the API's meta, to tell where a secret came from. Only short single-line strings, numbers, booleans and short lists are copied; `[]` copies none |
| `escrow.tcp` | `true` | Serve the API at `/_escrow/` on `listen.addr`. `false` leaves it only on `escrow.socket` (which it then needs); `/_escrow/` on the listener is 404 |
| `escrow.socket.path` | required with `socket` | Absolute path of a unix socket that serves the same API, at most 103 bytes. Its directory (symlinks resolved) must be root's or the gate's user's and writable by nobody else, except a sticky directory owned by root; prefer a directory of the gate's own, such as `/run/mcp-gate`, to a shared one like `/tmp`. The parent directory is created 0700 if missing; a stale socket file is replaced, anything else there stops the start; the file is removed at shutdown |
| `escrow.socket.allowUIDs` | none | User IDs served on the socket without a key, read from the kernel (`SO_PEERCRED`, `LOCAL_PEERCRED`). Every process of a listed user outside the gate's tree is trusted; on Linux the gate and its descendants (the stdio servers) still need the key, on macOS they do not. On Linux the check reads other users' `/proc` entries; where they are hidden (`ProtectProc=invisible`, `hidepid`), keyless access fails closed. Do not list the gate's own user: its stdio servers can start processes outside its tree (see [serve](../commands/serve.md#escrow-socket)). Other users need the key, as on the listener |
| `escrow.socket.mode` | `0600` | Permission bits of the socket file, in octal. `0600` admits only the gate's user and root; `0660` with a shared group admits the group's members, who need the key unless listed in `allowUIDs` |
| `aggregate` | none | Serve servers together at `/mcp`, tools and prompts named `<server>__<name>` (see [serve](../commands/serve.md#aggregate-endpoint)). `aggregate: {}` serves every enabled server; `aggregate:` without a value is an error |
| `aggregate.servers` | every server | The servers served at `/mcp`; not empty, no name twice. A disabled server is left out. A server served there cannot have `__` in its name or end in `_`, and its name is at most 61 characters |
| `aggregate.log.requests` | `false` | Log each HTTP request to `/mcp`, as `log.requests` does for a server |
| `policies.<token>.servers.<server>` | none | The token's own filters on that server, applied after the server's (see [Token policies](#token-policies)): `tools`, `prompts` and `resources`, at least one, each a non-empty `allow` or `deny` list or `none` |
| `servers.<name>` | | One downstream server. The name is lower-case letters, digits, `.`, `_` and `-`, up to 63 characters, and becomes the path `/<name>/mcp` |
| `stdio.command` | required | Program to start, without a shell; a name without `/` is looked up in the gate's `PATH` |
| `stdio.args` | none | Its arguments |
| `stdio.cwd` | the gate's | Absolute working directory |
| `stdio.env` | none | Variables set for the child; they win over inherited ones |
| `stdio.inheritEnv` | `PATH HOME LANG LC_* TZ USER XDG_RUNTIME_DIR` | The gate's variables the child inherits; `*` at the end matches a prefix; `[]` inherits nothing |
| `http.url` | required | The server's endpoint, `http` or `https`, without user information or fragment: the streamable HTTP endpoint, or with `transport: sse` the URL of the event stream (often ending in `/sse`) |
| `http.headers` | none | Headers sent with every request, such as an API key. Headers mcp-gate sets (`Accept`, `Accept-Encoding`, `Content-Type`, every `Mcp-` header and the like) cannot be set |
| `http.transport` | `streamable` | `streamable` for streamable HTTP, or `sse` for a server that speaks only the HTTP+SSE transport of protocol `2024-11-05`: a GET opens the event stream and messages are POSTed to the endpoint its first event names, which must be on the origin (scheme, host and port) of `url`. Such a server is offered `2025-11-25` and negotiates down; `protocolVersion` must be earlier than `2026-07-28`. Headers, OAuth, size limits, probes and restarts work as on streamable HTTP. A change restarts the server |
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
| `resources` | all | The same, matching a resource's URI or name and a template's URI template or name. Under a deny list, a read of a denied URI is refused in any spelling the gate can tell is the same, and so is any read whose URI a denied template matches, even when a narrower or wider visible template matches it too. Under an allow list, a read reaches only an allowed resource or goes through an allowed template, and another spelling of a listed resource the list hides is refused; an allow list is the safer choice |
| `auth.inherit` | `true` | Accept the global `auth.tokens` too |
| `auth.tokens` | none | Tokens this server accepts in addition; with `inherit`, their names differ from the global ones |
| `auth.public` | `false` | Serve without a token. Excludes `tokens` and `inherit` |
| `log.requests` | `false` | Log each HTTP request to the route: method, status, duration, remote address |
| `redact.enabled` | `true` | Redact results; see [Redaction](../architecture/redaction.md) |
| `redact.ru` | `false` | Add the Russian label rules |
| `redact.highEntropy` | `false` | Add the high-entropy rule |
| `redact.disableRules` | none | Redaction kinds never reported, such as `jwt` |
| `redact.escrow` | `true` | Keep this server's secrets and files in the escrow when it is on; `false` gives them plain `[REDACTED:<kind>]` markers and keeps nothing |
| `redact.escrowTTL` | `escrow.ttl` | How long the escrow keeps this server's secrets |
| `redact.files.tools` | required with `files` | Tools that save a file locally and report its path; the files they write are scanned and withheld when they hold secrets. Needs `redact.enabled` |
| `redact.files.roots` | required with `files` | Absolute directories the tools write to (not `/`, not `$HOME` or a directory above it); only files under them are read, and a path only the arguments name when written during the call; without a usable `$HOME` the check is skipped with a warning |
| `redact.files.maxBytes` | `20MiB` | Largest file scanned, `1KiB` to `1GiB`. A larger text file withholds the whole result; a larger binary file passes |
| `toolPins` | `warn` | What the gate does when the server lists a tool whose definition differs from its pin, or a new one: `warn` logs it and serves it, `hold` logs it and hides it until [`mcp-gate toolpins accept`](../commands/toolpins.md) accepts it (needs a state directory), `off` compares nothing (see [Tool pins](#tool-pins)) |
| `redact.arguments` | `log` | What a secret found in what a client sends does (a tool call's arguments, a prompt's arguments, a resource URI, scanned with this server's rules): `off` scans nothing, `log` forwards the request and names the kinds in the audit line's `argumentSecrets`, `block` refuses it (a tool error for a tool call). Escrow markers are never findings. `block` needs `redact.enabled` |
| `redact.substitute` | none | Where an escrow handle in a tool call's arguments is replaced by its value before the call is forwarded (see [Argument secrets](#argument-secrets)). A list of rules, each with `tool`, `argument` and `from`. Needs `redact.enabled` |
| `substitute[].tool` | required | The server's own name of the tool |
| `substitute[].argument` | required | Path of member names joined by `.` to a string value in the arguments, such as `auth.password`; `*` matches any member or array element, a number the element at that index |
| `substitute[].from` | required | Map from the server a handle came from to the redaction kinds from it that may go here, such as `{notes: [password]}`; the server may be this one |
| `forwardMeta` | none | `_meta` keys of a client request passed to the server, by exact name, such as `example.com/trace`. Others are dropped: they describe the client. `progressToken` and `mcp`/`modelcontextprotocol`-prefixed keys are the gate's and cannot be listed |

Each server has exactly one of `stdio` and `http`. Every server that is not `public` must accept at least one token, and no two tokens a server accepts may have the same value. Token names are lower-case letters, digits, `.`, `_` and `-`; values may not contain spaces or control characters.

## Token policies

`policies.<token>.servers.<server>` narrows what one token sees and may call on one server. Its `tools`, `prompts` and `resources` are matched like a server's filters of the same name, by the same keys, and apply after them: an entry reaches the token only when both pass it. Each is a non-empty `allow` list, a non-empty `deny` list, or `none`, which hides every entry of its kind (`tools: none`). Empty lists, and a filter written without a value (`tools:` or `tools: ~`), are rejected, since a server's empty tool allow list exposes every tool and a snippet moved from one to the other would then fail open; `mcp-gate check` names `none` in its error. Entries are the server's own names, without the `<server>__` prefix of `/mcp`, and have no surrounding space. A filter left out, and a server the policy does not name, narrow nothing. The policy holds on the server's own route and on `/mcp` alike (see [serve](../commands/serve.md#token-policies)).

The key under `policies` is a token name as each server knows it: a token from `auth.tokens` on the servers that inherit them, and a server's own `auth.tokens` entry on that server. Two servers with `inherit: false` may each have their own token of the same name, with different values; a policy under that name applies on each server to that server's token. Each server named must exist and accept the token; a public server takes no token, so it cannot be named. `mcp-gate check` reports a policy that breaks these rules, such as `policies.phone.servers.nope: is not a server in servers`, and warns about a policy on a disabled server, which has no effect until the server is enabled. It also warns about a server's `tools: {allow: []}`, which exposes every tool.

## Argument secrets

An agent that should use a secret without seeing it passes the marker it was shown, `[REDACTED:password #k3j5abcdefg]`, in a tool call's arguments. When a rule of `redact.substitute` matches the tool and the argument's path, the gate replaces the marker by the value it holds in the escrow, but only when the escrow is on, the handle is live, the caller's token received that handle in a result, and the rule's `from` lists the server the secret came from with its kind. Otherwise the call is refused and nothing is sent. A marker in an argument no rule covers is sent as text. Each substitution is in the audit line's `substitutions` as `<handle>:<kind>:<origin>:<argument>`, never with the value. If the server sends the value back, the answer still carries the marker the agent passed.

Rules decide where secrets may flow: `from: {mail: [password]}` on a messaging server lets a password from `mail` be sent there, so keep rules to the tools and arguments that need them. A rule binds an argument, not a destination: the server sends the value wherever its other arguments say, so a rule on a `fetch` tool's `body` lets the agent post the secret to any `url`. Write rules only for tools whose destination is fixed, such as a login to one service. The value also reaches the client when the server returns it transformed (in another case, split or encoded other than percent-encoding or base64).

With `redact.arguments: block` on the same server, a secret the agent writes out in full is refused, while the handles substitution replaces are not. The scan catches secrets sent by mistake; an agent that means to send one can hide it (behind `[REDACTED`, encoded or split), so `block` is no barrier against a hostile agent.

## Values

- Durations are strings with a unit: `500ms`, `30s`, `2m`, `1h`. Sizes are strings with a binary unit: `512KiB`, `16MiB`. A bare number is rejected.
- `${NAME}` in any string value is replaced by the environment variable `NAME`; an unset or empty variable is an error. `$$` is a literal `$`; any other `$` is kept. Expansion happens after the YAML is parsed, so a value can never add keys.
- Secrets belong in the environment (for example a systemd `EnvironmentFile=`), referenced with `${NAME}`.

Errors name the field, such as `servers.notes.stdio.cwd: must be an absolute path`, and never print values.

## Tool pins

A server could change a tool's description or schema after you looked at it, to steer the model, for example by asking it to pass a file's contents to another tool. With `toolPins` at `warn` (the default) or `hold`, the gate pins the definition of every tool a server lists the first time it lists any: everything the gate serves of the tool, its `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons` and `_meta`, hashed with SHA-256. `_meta` is pinned since some of its keys steer clients, such as the UI resource a result is shown in; a server that puts something in it that changes on every listing needs `toolPins: off`. Every later listing is compared with the pins. A tool whose definition differs is `changed`, a tool not listed before is `added`; the gate logs either as a `toolPin` line (see [serve](../commands/serve.md#logs)), at most 20 a minute per server (the rest in a later minute, first and if still listed, with a line that names a few of them meanwhile), and keeps the listed definition as pending. A tool the server stops listing keeps its accepted pin, so a listing that misses it changes nothing. A name the server lists twice counts as first listed; the gate logs the others.

Under `warn` the tool is served as listed. Under `hold` it is left out of the server's catalog, of every token's view and of `/mcp`, and a call of it fails as one of a tool the server does not have, until `mcp-gate toolpins accept` accepts it and the gate is reloaded (see [toolpins](../commands/toolpins.md)); the previous definition is not served in its place, since the server would run its new implementation. When the pins of a server under `hold` cannot be read, or its first pins cannot be written, every one of its tools is held. A new tool under `hold` is held as well, so a server under `hold` that adds tools needs them accepted.

`hold` needs a state directory (`serve -state-dir`), where the pins are kept and accepted: without one the gate refuses to start, and a reload that sets `hold` is refused. Without a state directory, `warn` keeps the pins in memory, so a change is noticed only while the process runs.
