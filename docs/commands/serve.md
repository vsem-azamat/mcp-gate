# serve

[Docs](../README.md) / [Commands](README.md) / **serve**

`mcp-gate serve <file>` runs the gate: it starts every enabled server of the config and serves each at `/<name>/mcp` on `listen.addr`. The behaviour is specified in [`openspec/specs/serving/spec.md`](../../openspec/specs/serving/spec.md); the keys are in [Configuration](../configuration/README.md).

```sh
mcp-gate check gate.yaml        # validate first
mcp-gate serve -state-dir /var/lib/mcp-gate gate.yaml
```

The config is validated as `check` does; an invalid one exits with status 2 before anything starts. Logs are JSON lines on stderr, at `logLevel` and above. SIGINT and SIGTERM shut the gate down: it stops accepting connections, gives calls in flight 10 seconds, and stops the servers. Exit status: 0 after a clean shutdown, 2 when the config is invalid or the gate cannot listen.

`-state-dir` is where the gate keeps the protocol pins it learns (`pins.json`), so that a server that ignores `server/discover` does not cost the 5 second sub-deadline again after a restart. It defaults to the first directory of `$STATE_DIRECTORY`, which systemd sets for a unit with `StateDirectory=`; without one, pins last only while the process runs. Delete the file to make the gate try discover again.

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
| `/_readyz` | none | 200 `ok`; 503 `initializing` during `startupGracePeriod`, `degraded` (with `unhealthy`) while a connected server is down, `unavailable` when no server ever connected |
| `/_status` | an `admin.tokens` token | Per-server state, protocol version, pins, restarts, last error, PID and memory, catalog counts, call counts |

```console
$ curl -s http://127.0.0.1:9090/_readyz
{"name":"mcp-gate","serverCount":3,"status":"degraded","unhealthy":["shop"],"version":"v0.3.0"}
$ curl -s -H "Authorization: Bearer $GATE_ADMIN_TOKEN" http://127.0.0.1:9090/_status
```

## Logs

Every forwarded call writes one `call` line with the server, the token name (`principal`), the method, the tool or prompt or resource URI, the duration, the outcome and the number of redactions; arguments and results are never logged:

```json
{"time":"…","level":"INFO","msg":"call","server":"notes","principal":"laptop","method":"tools/call","tool":"search","durMs":412,"outcome":"ok","redactions":0}
```

With `log.requests`, each HTTP request to the route also writes a `request` line with its method, status, duration and remote address.
