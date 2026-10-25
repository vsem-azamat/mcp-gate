# serve

[Docs](../README.md) / [Commands](README.md) / **serve**

`mcp-gate serve <file>` runs the gate: it starts every enabled server of the config and serves each at `/<name>/mcp` on `listen.addr`. The behaviour is specified in [`openspec/specs/serving/spec.md`](../../openspec/specs/serving/spec.md); the keys are in [Configuration](../configuration/README.md).

```sh
mcp-gate check gate.yaml        # validate first
mcp-gate serve -state-dir /var/lib/mcp-gate gate.yaml
```

The config is validated as `check` does; an invalid one exits with status 2 before anything starts. Logs are JSON lines on stderr, at `logLevel` and above. SIGINT and SIGTERM shut the gate down: it stops accepting connections, gives calls in flight 10 seconds, and stops the servers. Exit status: 0 after a clean shutdown, 2 when the config is invalid or the gate cannot listen.

`-state-dir` is where the gate keeps the protocol pins it learns (`pins.json`), so that a server that ignores `server/discover` does not cost the 5 second sub-deadline again after a restart, and the OAuth grants (`oauth/<server>.json`, see [auth](auth.md)). It defaults to the first directory of `$STATE_DIRECTORY`, which systemd sets for a unit with `StateDirectory=`; without one, pins last only while the process runs and OAuth servers cannot log in. Delete `pins.json` to make the gate try discover again.

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

A route answers 503 with `Retry-After: 5` until its server has connected once. After that, a restart of the server keeps its catalog: listing still works, and calls fail with a tool error saying the server is not available until it is back.

## Health and status

| Path | Token | Answer |
| --- | --- | --- |
| `/_healthz` | none | 200 `ok` while the process serves |
| `/_readyz` | none | 200 `ok`; 503 `initializing` during `startupGracePeriod`, `degraded` (with `unhealthy`) while a connected server is down or (with `needsLogin`) while a server needs an OAuth login, `unavailable` when no server ever connected |
| `/_status` | an `admin.tokens` token | Per-server state, protocol version, pins, restarts, last error, PID and memory, catalog counts, call counts |

```console
$ curl -s http://127.0.0.1:9090/_readyz
{"name":"mcp-gate","serverCount":3,"status":"degraded","unhealthy":["shop"],"version":"v0.3.0"}
$ curl -s -H "Authorization: Bearer $GATE_ADMIN_TOKEN" http://127.0.0.1:9090/_status
```

## Escrow

With `MCP_HUB_ESCROW_KEY_SHA256` set to the hex SHA-256 of an API key, the gate keeps every secret it redacts from results in memory, for `escrow.ttl` (or the server's `redact.escrowTTL`), and writes `[REDACTED:<kind> #<handle>]` in its place. The owner releases a secret with the key; clients' tokens do not open it. Nothing is written to disk, so a restart forgets every secret. A value that is not a hex SHA-256 stops the gate at start.

```console
$ key=$(openssl rand -hex 32)
$ export MCP_HUB_ESCROW_KEY_SHA256=$(printf %s "$key" | sha256sum | cut -d' ' -f1)
$ mcp-gate serve gate.yaml &
$ curl -s -H "Authorization: Bearer $key" http://127.0.0.1:9090/_escrow/k3j5rz2q7wd/meta
{"handle":"k3j5rz2q7wd","type":"password","kind":"text","server":"notes","tool":"read_note","source":{},"created_at":"…","expires_at":"…","preview":"Summ…77!"}
$ curl -s -H "Authorization: Bearer $key" http://127.0.0.1:9090/_escrow/k3j5rz2q7wd
$ curl -s -X DELETE -H "Authorization: Bearer $key" http://127.0.0.1:9090/_escrow/k3j5rz2q7wd
```

| Request | Answer |
| --- | --- |
| `GET`/`HEAD /_escrow/<handle>/meta` | JSON: handle, type, kind (`text` or `file`), server, tool, source (identifying arguments such as `chat_id`), times, a short preview; `file_name` and `size` for a file |
| `GET /_escrow/<handle>` | The value (or the file, while unchanged) as `application/octet-stream` |
| `DELETE /_escrow/<handle>` | 204; the entry is gone |

A wrong or missing key is 401 on every path; 20 wrong keys from one client address give 429 until it has waited (one more attempt every 3 seconds). Requests without a key do not count. Behind a reverse proxy on the same host, set `listen.behindProxy` so that the limit is kept per client (`X-Forwarded-For`), not for the proxy as a whole. Files that a server's `redact.files.tools` write are kept the same way, as `[REDACTED:file #<handle>]`.

## Logs

Every forwarded call writes one `call` line with the server, the token name (`principal`), the method, the tool or prompt or resource URI, the duration, the outcome and the number of redactions; arguments and results are never logged:

```json
{"time":"…","level":"INFO","msg":"call","server":"notes","principal":"laptop","method":"tools/call","tool":"search","durMs":412,"outcome":"ok","redactions":0}
```

With `log.requests`, each HTTP request to the route also writes a `request` line with its method, status, duration and remote address.
