# serve

[Docs](../README.md) / [Commands](README.md) / **serve**

`mcp-gate serve <file>` runs the gate: it starts every enabled server of the config and serves each at `/<name>/mcp` on `listen.addr`. The behaviour is specified in [`gate-lifecycle`](../../openspec/specs/gate-lifecycle/spec.md), [`routes-and-auth`](../../openspec/specs/routes-and-auth/spec.md), [`serving`](../../openspec/specs/serving/spec.md), [`aggregate-endpoint`](../../openspec/specs/aggregate-endpoint/spec.md), [`token-policies`](../../openspec/specs/token-policies/spec.md) and [`reload`](../../openspec/specs/reload/spec.md); the keys are in [Configuration](../configuration/README.md).

```sh
mcp-gate check gate.yaml        # validate first
mcp-gate serve -state-dir /var/lib/mcp-gate gate.yaml
```

The config is validated as `check` does; an invalid one exits with status 2 before anything starts. Logs are JSON lines on stderr, at `logLevel` and above. SIGINT and SIGTERM shut the gate down: it stops accepting connections, gives calls in flight 10 seconds, and stops the servers. SIGHUP reloads the config (see [Reload](#reload)). Exit status: 0 after a clean shutdown, 2 when the config is invalid or the gate cannot listen.

Under systemd the gate serves the listening socket that a socket unit passes it (`LISTEN_FDS`), instead of opening `listen.addr`, and reports `READY=1` once startup is over and `STOPPING=1` at shutdown (`NOTIFY_SOCKET`). With the socket held by systemd, a restart refuses no connection and fails no call; see [systemd](../operations/systemd.md#restarts) for the units and what a restart keeps.

`-state-dir` is where the gate keeps the protocol pins it learns (`pins.json`), so that a server that ignores `server/discover` does not cost the 5 second sub-deadline again after a restart, and the OAuth grants (`oauth/<server>.json`, see [auth](auth.md)). It defaults to the first directory of `$STATE_DIRECTORY`, which systemd sets for a unit with `StateDirectory=`; without one, pins last only while the process runs and OAuth servers cannot log in. A pin holds while the server's command, arguments and working directory (or URL) stay the same; a changed or removed server loses its pin. Delete `pins.json` to make the gate try discover again.

An OAuth server without a usable grant is `needs-login`: it sends nothing to the server, its route answers 503 until it has connected once, and its calls fail. It picks up a login made with `mcp-gate auth login` at its next attempt, within `restart.maxBackoff`, without a restart.

## Clients

A client connects to `http://<listen.addr>/<name>/mcp` with one of the server's tokens:

```json
{
  "mcpServers": {
    "notes": {
      "type": "http",
      "url": "https://mcp.example.com/notes/mcp",
      "headers": {"Authorization": "Bearer <token>"}
    }
  }
}
```

With `aggregate` in the config, one entry reaches many servers at `/mcp` (see [Aggregate endpoint](#aggregate-endpoint)).

A request that arrives while the gate is starting is held until its server has connected, or `startupGracePeriod` ends. After startup, a route answers 503 with `Retry-After: 5` until its server has connected once. After that, a restart of the server keeps its catalog: listing still works, and calls fail with a tool error saying the server is not available until it is back.

## Aggregate endpoint

`aggregate: {}` serves every enabled server, or those in `aggregate.servers`, together at `/mcp`:

```json
{
  "mcpServers": {
    "gate": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": {"Authorization": "Bearer <token>"}
    }
  }
}
```

- **Names.** Tools and prompts are named `<server>__<name>`, such as `notes__search`. A tool or prompt name that would be longer than 64 characters, or hold characters other than letters, digits, `_`, `.` and `-`, is left out, with a warning in the log; it is still on its server's own route. A server on the endpoint cannot have `__` in its name or end in `_`, so a name splits one way only, and its name is at most 61 characters, so that a prefixed name fits.
- **Resources** keep their URIs. A read goes to the server that lists the URI, or else to the one whose template matches it. A URI or template that two of the caller's servers both list is left out, with a warning in the log, and a read no single server claims fails; read those on the server's own route.
- **Tokens.** A token sees and calls only the servers whose own routes accept it, plus the public ones; without a token, only the public ones. A token that no server on the endpoint accepts gets 401, even when some are public. If every server listed in `aggregate.servers` is disabled, `/mcp` answers every request with 401 and the gate logs a warning at start. Each call is checked again against its server before it is forwarded.
- **The same handling.** A call runs through its server exactly as on `/<server>/mcp`: filters, token policies, `callTimeout`, progress, cancellation, redaction, file scanning, escrow, and the `call` log line, which names the real server and the token name that server knows.
- **Changes.** A server's new or removed tools reach the endpoint, and clients listening for changes are told. A server that is down keeps its tools there, as on its own route; one that never connected, or waits for a login, has none until it does.
- A request to `/mcp` that arrives while the gate is starting is held until every server the caller reaches has listed its catalog or waits for a login, or startup is over. `/_readyz` and `/_status` report servers, not the endpoint.

## Token policies

`policies` gives a token its own allow or deny lists on some servers, on top of the servers' own (see [Configuration](../configuration/README.md#token-policies)). The token's lists show only what its lists pass, and a call, prompt get or resource read of something they hide fails exactly as one of a name the server does not have, so a token cannot tell a hidden tool or prompt from a missing one. The `call` line records the decision in `tokenPolicy`; a name the server does not have, or one its own filter hides, is `none`, since no policy decided it. On a server where any token has a policy, results carry the cache scope `private`, since the lists depend on the token. The capabilities a server advertises do not depend on the token: a policy that hides every prompt leaves the prompt list empty.

A resource read passes when the resource listed under its URI passes, or, when none is, a template that matches it does; a read in another spelling of a listed resource the policy hides is refused too. Resources are not hidden as well as tools: when a policy allows a template that also matches the URI of a listed resource it hides, a read of that URI fails while other URIs through the template succeed, so a token can find hidden URIs by guessing. Under an allow list, a read through an allowed template reaches whatever the server serves for that URI, as with a server's allow list, so allow templates only when every URI they match may be read. The comparison of spellings ignores invisible characters, such as a zero-width space or a variation selector, in the path and the query, and Unicode spaces around a path segment, so a listed resource the policy hides also refuses an allowed URI that differs from it only by such characters. Letters, encoded or not, are kept, so `fake://caf%C3%A9` is its own resource; format characters are removed even where a font draws them (such as the Arabic number sign), which only refuses more. It lower-cases the scheme and the authority, which for URIs such as `fake://hidden` is the resource's own name, so on a server where that part is case-sensitive it refuses more than the one resource. Under a deny list the comparison ignores the query, so every query of a hidden URI is refused. Under an allow list, a hidden URI without a query refuses every query of it, and a hidden URI with a query refuses the reads whose query holds all of its parameters, however written (in another order, with other parameters, repeated, in other letter case, with `;` or `+`, or with leading zeros), so that hiding `db://t?id=1` does not refuse `db://t?id=2` read through an allowed template.

## Health and status

| Path | Token | Answer |
| --- | --- | --- |
| `/_healthz` | none | 200 `ok` while the process serves |
| `/_readyz` | none | 200 `ok`; 503 `initializing` during `startupGracePeriod`, `degraded` (with `unhealthy`) while a connected server is down or (with `needsLogin`) while a server needs an OAuth login, `unavailable` when no server ever connected |
| `/_status` | an `admin.tokens` token | Per-server state, protocol version, pins, restarts, last error, PID and memory, catalog counts, call counts |
| `/_metrics` | an `admin.tokens` token; none on `metrics.addr` | Prometheus metrics, with `metrics.enabled` or `metrics.addr` (see [Metrics](../operations/metrics.md)) |

```console
$ curl -s http://127.0.0.1:9090/_readyz
{"name":"mcp-gate","serverCount":3,"status":"degraded","unhealthy":["shop"],"version":"v0.3.0"}
$ curl -s -H "Authorization: Bearer $GATE_ADMIN_TOKEN" http://127.0.0.1:9090/_status
```

## Escrow

With the hex SHA-256 of an API key configured, the gate keeps every secret it redacts from results in memory, for `escrow.ttl` (or the server's `redact.escrowTTL`), and writes `[REDACTED:<kind> #<handle>]` in its place. The owner releases a secret with the key; clients' tokens do not open it. Nothing is written to disk, so a restart forgets every secret. A server with `redact.escrow: false` keeps nothing and gets plain `[REDACTED:<kind>]` markers.

The key hash comes from the first of these that is set:

| Source | Notes |
| --- | --- |
| `escrow.keyHash` in the config | As `${VAR}`; prefer setting `MCP_GATE_ESCROW_KEY_SHA256` itself |
| `escrow.keyHashFile` in the config | A file holding the hash, read at start: a systemd credential, a mounted secret. Regular file, owned by root or the gate's user (any owner when the gate runs as root), not writable by group or others |
| `MCP_GATE_ESCROW_KEY_SHA256` | The environment variable |
| `MCP_HUB_ESCROW_KEY_SHA256` | Deprecated name of the same variable, still read; the gate logs a warning at start |

Every source that is set must hold the same hash: two different hashes stop the gate at start, as does a value that is not a hex SHA-256. Neither variable, nor a variable that `escrow.keyHash` names, is passed on to stdio servers. `mcp-gate check` prints whether the escrow would be on and which source the hash comes from (see [check](check.md)).

```console
$ key=$(openssl rand -hex 32)
$ export MCP_GATE_ESCROW_KEY_SHA256=$(printf %s "$key" | sha256sum | cut -d' ' -f1)
$ mcp-gate serve gate.yaml &
$ curl -s -H "Authorization: Bearer $key" http://127.0.0.1:9090/_escrow/k3j5rz2q7wd/meta
{"handle":"k3j5rz2q7wd","type":"password","kind":"text","server":"notes","tool":"read_note","source":{},"created_at":"…","expires_at":"…","preview":"Summ…77!"}
$ curl -s -H "Authorization: Bearer $key" http://127.0.0.1:9090/_escrow/k3j5rz2q7wd
$ curl -s -X DELETE -H "Authorization: Bearer $key" http://127.0.0.1:9090/_escrow/k3j5rz2q7wd
```

| Request | Answer |
| --- | --- |
| `GET`/`HEAD /_escrow/<handle>/meta` | JSON: handle, type, kind (`text` or `file`), server, tool, source (the call's arguments named in `escrow.sourceArguments`, such as `chat_id`), times, a short preview; `file_name` and `size` for a file |
| `GET /_escrow/<handle>` | The value (or the file, while unchanged) as `application/octet-stream` |
| `DELETE /_escrow/<handle>` | 204; the entry is gone |

A wrong or missing key is 401 on every path; 20 wrong keys from one client address give 429 to any key from it, the right one included, until it has waited (one more attempt every 3 seconds), and 100 wrong keys from all clients together give 429 to further wrong keys (one more a second), never to the right key. Requests without a key do not count. The limit only slows guessing: generate the key with at least 128 random bits, as above. Behind a reverse proxy on the same host, set `listen.behindProxy` so that the limit is kept per client (`X-Forwarded-For`), not for the proxy as a whole; the gate warns at start when the escrow is on a loopback listener without it. Files that a server's `redact.files.tools` write are kept the same way, as `[REDACTED:file #<handle>]`.

### Escrow socket

With `escrow.socket`, the same API is also served on a unix socket. By default it needs the key like the listener. The kernel tells the gate which user connected; a user listed in `escrow.socket.allowUIDs` needs no key there, and any other user needs the key, exactly as on the listener. With `escrow.tcp: false` the listener no longer answers `/_escrow/`, so a reverse proxy in front of the gate cannot reach the API at all.

```console
$ curl -s --unix-socket /run/mcp-gate/escrow.sock http://escrow/_escrow/k3j5rz2q7wd/meta
{"handle":"k3j5rz2q7wd","type":"password",…}
```

Listing a user ID trusts every process of that user outside the gate's process tree: a shell, an agent, a reverse proxy that would forward to the socket. On Linux the gate itself and its descendants, its stdio servers and anything they start, still need the key even when their user ID is listed: the gate reads the peer's process ID from the kernel and walks its parents, and a peer it cannot place needs the key too. The tree check is defense in depth, not a boundary: a stdio server can start a process of the same user outside the gate's tree (`systemd-run --user`, tmux, ssh, D-Bus, `ptrace`), which is then served without the key. Listing the gate's own user ID therefore lets its stdio servers read every escrowed secret, and the gate warns at start when `allowUIDs` holds it. The walk reads the `/proc` entries of other users' processes, the peer's and ancestors such as `sshd`; where they are hidden (`ProtectProc=invisible`, as in the shipped system unit, or a `hidepid` mount) it cannot place the peer and keyless access fails closed: every request needs the key, and the gate warns at start. The process ID is the one the peer had when it connected; a gate descendant that exits and whose ID is reused before the request is a race, which only matters when the gate's own user ID is listed. On macOS the tree is not checked at all. Run the gate as a user of its own and list only the reader's user ID.

The access log names a socket client `unix:uid=<n>`, and the failed-auth limit counts per user ID; a request served without a key skips it. The socket's directory, with symlinks resolved, must be root's or the gate's user's and writable by nobody else (a sticky directory only when root's), or the gate does not start. Even so, do not put the socket in a shared sticky directory such as `/tmp`: while the gate is down, another user can create a socket of their own at the path and collect the key a client sends. Use a directory of the gate's own, such as a systemd `RuntimeDirectory=`. The default mode `0600` admits only the gate's user and root; a reader running as another user needs a shared group, as in [systemd](../operations/systemd.md#escrow-socket). Where the system does not report the peer's user (on systems other than Linux and macOS), every socket request needs the key.

## Logs

Every forwarded call writes one `call` line with the server, the token name (`principal`), the method, the tool or prompt or resource URI, the duration, the outcome, what the token's policy decided (`tokenPolicy`: `none` without a policy on the server, `allow` or `deny`) and the number of redactions; arguments and results are never logged:

```json
{"time":"…","level":"INFO","msg":"call","server":"notes","principal":"laptop","method":"tools/call","tool":"search","durMs":412,"outcome":"ok","tokenPolicy":"none","redactions":0}
```

A call a token's policy hides is a line with outcome `denied` and `tokenPolicy` `deny`.

With `log.requests`, each HTTP request to the route also writes a `request` line with its method, status, duration and remote address; `aggregate.log.requests` does the same for `/mcp`, with `server` `/mcp`. A call the aggregate endpoint refuses before any server sees it (a name of a server the token does not reach, say) is a `call` line with outcome `denied` and an empty `server`.

## Reload

SIGHUP (`systemctl reload mcp-gate`) makes the gate read its config file again. A config that does not load or pass validation is logged as an error and the gate goes on with the one it has; `mcp-gate check` accepts exactly the configs a reload applies, so run it first. A valid one replaces the running config at one instant: requests that arrive from then on are served under it, and requests already in flight finish under the old one, so a call never runs with half of each.

| Change | Effect |
| --- | --- |
| A server's `stdio` or `http` (command, arguments, environment, URL, headers, OAuth), `callTimeout`, `maxMessageBytes`, `protocolVersion`, `probeInterval`, `restart`, `disabled`, or the config's `name` | The server restarts once the requests in flight on the routes that reach it have ended (at most 10 seconds); meanwhile requests to it are held until it is back, at most `startupGracePeriod`. Added servers start after that, and a replacement waits for an old process that is slow to end |
| A server's `tools`, `prompts`, `resources`, `redact`, `forwardMeta`; the token policies on it; `escrow.ttl` | At once, the server keeps running; the `subscriptions/listen` streams of its routes end |
| Tokens (`auth`, a server's `auth`), a server's `log`, `aggregate`, `listen.allowedHosts`, `listen.behindProxy`, `listen.trustedProxies` | At once: a removed token gets 401 from its next request, and a call it began before completes. Only the routes whose tokens or settings changed are replaced, ending their listen streams |
| `logLevel`, `admin`, `metrics.enabled` | At once; the metrics' counts are kept |
| `listen.addr`, `metrics.addr`, `escrow` (but `escrow.ttl`), `startupGracePeriod` | Only at the next restart; the reload logs a warning |

A request whose body is still arriving when a reload revokes its token, or that is held while the gate starts, is checked again under the new config. `${VAR}` values come from the environment the gate started with, so a token added to the environment needs a restart. Each reload logs `config reloaded` with the servers added, restarted, removed and kept. Under systemd, once startup is over, the gate reports `RELOADING=1` and then `READY=1`; `systemctl reload` itself returns as soon as the signal is sent, so the outcome of a reload is in the log. A SIGHUP during startup is applied without a report.
