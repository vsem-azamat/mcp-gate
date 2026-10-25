# Serving

[Docs](../README.md) / [Architecture](README.md) / **Serving**

How `mcp-gate serve` puts the downstream servers behind one listener. The behaviour is specified in [`openspec/specs/serving/spec.md`](../../openspec/specs/serving/spec.md).

## Packages

| Package | Contents |
| --- | --- |
| [`internal/gate`](../../internal/gate/gate.go) | Assembles the gate from the config: a supervisor and a mirror per server, the routes, readiness after the startup grace period, `/_status`, the learned pins file, shutdown |
| [`internal/upstream`](../../internal/upstream/http.go) | The HTTP side: listener limits, body limit, Host check, named tokens, request log, panic recovery, `/_healthz`, `/_readyz` and `/_status` handlers |
| [`internal/proxy`](../../internal/proxy/mirror.go) | `Mirror`: the upstream MCP server of one downstream, its catalog sync, call forwarding, progress, notifications, redaction of results and the audit line |
| [`internal/policy`](../../internal/policy/policy.go) | Tool, prompt and resource filters, and the URI check for resource reads |

## Request path

```
client ─POST /<name>/mcp─▶ Recover ─▶ LogRequests (log.requests) ─▶ AllowHosts ─▶ RequireToken
   ─▶ CrossOriginProtection ─▶ 503 until mounted ─▶ ReadBody (4 MiB, 30 s)
   ─▶ SDK StreamableHTTPHandler (stateless) ─▶ Mirror's mcp.Server ─▶ handler
   ─▶ Supervisor.Call ─▶ downstream ClientSession
```

The upstream side is the SDK's streamable HTTP handler in stateless mode, with `PropagateRequestCancellation`: every POST gets a fresh `ServerSession` over the mirror's one `*mcp.Server`, and the handler's context ends with the POST. Nothing about a client is kept between requests, so any number of clients share the one downstream session that the supervisor keeps. The listener has no read timeout, since net/http would cancel a long call's context when it passes; `ReadBody` reads the body under its own deadline and clears it.

`RequireToken` checks the `Authorization` header against SHA-256 digests of the route's tokens, every one compared in constant time, and hands the token's name to the SDK's bearer middleware as the `TokenInfo` user, where the handlers read it for the audit line.

## Mirror

A `Mirror` registers the downstream catalog on its `*mcp.Server` with `AddTool`, `AddPrompt`, `AddResource` and `AddResourceTemplate`, each with a handler that forwards to the supervisor. Its capabilities are fixed when it is created, from the policy alone, so a client sees the same ones whether or not the server is up.

The sync loop lists what is marked dirty: everything on each new downstream session (the supervisor's `OnSession` hook), a kind on its list-changed notification. A failed listing keeps what was there and is retried with backoff; without a session it waits for the next one. Applying a listing compares each entry with the registered one by its JSON encoding and changes only those that differ, so a resync that finds nothing new sends clients no notification. The SDK panics on entries it rejects (a tool schema that is not an object); `validTool` catches the usual case first so the log can say why, and `guard` recovers the rest.

A forwarded call builds the downstream `_meta` (`downstreamMeta`), opens a progress sink when the client asked for progress, and runs the request in `Supervisor.Call` on the upstream request's context. The progress sink has a gate token (`mcp-gate-<n>`) that the downstream sees, keeps only the newest unsent notification and sends it from its own goroutine on the upstream request's `ServerSession`, so a client that does not read blocks only its sink.

Downstream notifications arrive from the SDK one at a time on the session's reader, so the handlers only enqueue (64 deep, counting what they drop) and one worker per mirror delivers progress and logs the server's log messages.

Results go through `mcpredact` with the server's engine and a replacer: `redact.Marker` by default, or what `gate.Options.Replacer` returns for the server, which is where a replacer that keeps values plugs in. Each call counts its findings through a wrapping replacer for the audit line.

## Readiness and status

`Gate.Run` starts every supervisor and mirror, then serves. A watcher marks the gate started once every mirror has listed its catalog, or when `startupGracePeriod` ends. `/_readyz` reads `Gate.Readiness`: a server counts as mounted once its catalog was listed, and as unhealthy while mounted and in a state other than `ready` or `degraded`. `/_status` merges `Supervisor.Status` with `Mirror.Stats`, and reads the child's resident memory from `/proc/<pid>/statm`.

## Learned pins

The supervisor reports an automatic protocol pin through `OnPinLearned`. The gate writes all pins to `pins.json` in the state directory (temporary file, sync, rename) and passes each to its supervisor as `LearnedPin` at the next start.
