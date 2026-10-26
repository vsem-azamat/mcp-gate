# Serving

[Docs](../README.md) / [Architecture](README.md) / **Serving**

How `mcp-gate serve` puts the downstream servers behind one listener. The behaviour is specified in [`openspec/specs/serving/spec.md`](../../openspec/specs/serving/spec.md).

## Packages

| Package | Contents |
| --- | --- |
| [`internal/gate`](../../internal/gate/gate.go) | Assembles the gate from the config: a supervisor and a mirror per server, the routes, readiness after the startup grace period, `/_status`, the learned pins file, reloads, shutdown |
| [`internal/upstream`](../../internal/upstream/http.go) | The HTTP side: listener limits, the drain at shutdown, body limit, Host check, named tokens, request log, panic recovery, `/_healthz`, `/_readyz` and `/_status` handlers |
| [`internal/systemd`](../../internal/systemd/systemd.go) | Socket activation (the listener systemd passes) and readiness notification (`sd_notify`), without a systemd library |
| [`internal/proxy`](../../internal/proxy/mirror.go) | `Source`: the catalog sync, counters, progress and notifications of one downstream; `Mirror`: its upstream MCP servers under one config (one per token with a policy), call forwarding, redaction of results and the audit records; `Aggregate` and `View`: the catalogs of several mirrors at `/mcp` |
| [`internal/audit`](../../internal/audit/audit.go) | The audit record of a request (`audit.Record`, its `Kind` and `Outcome`), the `Sink` interface and the sink that writes `call` lines |
| [`internal/policy`](../../internal/policy/policy.go) | Tool, prompt and resource filters, per-token policies and their decisions, and the URI check for resource reads |

## Request path

```
client ─POST /<name>/mcp─▶ Recover ─▶ LogRequests (log.requests) ─▶ AllowHosts ─▶ RequireToken
   ─▶ CrossOriginProtection ─▶ 503 until mounted (held during startup) ─▶ ReadBody (4 MiB, 30 s) ─▶ respond
   ─▶ SDK StreamableHTTPHandler (stateless; event stream or JSONResponse) ─▶ Mirror's mcp.Server ─▶ receive middleware ─▶ handler
   ─▶ request pipeline ─▶ Supervisor.CallTool / GetPrompt / ReadResource ─▶ downstream ClientSession
```

`/_healthz`, `/_readyz`, `/_status` and, with the escrow on, `/_escrow/` are separate handlers on the same mux, outside this chain (see [Escrow and file scanning](escrow.md)).

The upstream side is the SDK's streamable HTTP handler in stateless mode, with `PropagateRequestCancellation`: every POST gets a fresh `ServerSession` over the mirror's one `*mcp.Server`, and the handler's context ends with the POST. Nothing about a client is kept between requests, so any number of clients share the one downstream session that the supervisor keeps. The listener has no read timeout, since net/http would cancel a long call's context when it passes; `ReadBody` reads the body under its own deadline and clears it.

A route has two SDK handlers over the same `*mcp.Server`, identical but for `JSONResponse`, and `respond` picks one per POST from the body that `ReadBody` kept (`upstream.BodyBytes`). The only messages the gate sends on a request's stream besides its response are progress notifications for a request with a progress token: a stateless session cannot send requests (sampling, elicitation), the mirror logs the server's log messages instead of forwarding them, and list-changed notifications reach only `subscriptions/listen` streams. So one JSON-RPC object without `_meta.progressToken` that is not `subscriptions/listen` goes to the `JSONResponse` handler, which writes the response as one `application/json` body, and the rest to the event-stream handler. `classify` decides without decoding when the body holds neither `progressToken` nor `listen` (which `subscriptions\/listen` also spells) nor a `\u` escape that could spell one, and otherwise decodes the method and `_meta` with the SDK's decoder settings (segmentio, exact field names, a repeated `_meta` merged), so that it finds the progress token the SDK finds. A request the client cannot be answered for (it accepts neither type, or `subscriptions/listen` without `text/event-stream`) gets 400 from `respond` itself. The MCP transport requires clients to accept both types; one that names only one gets it, with its `Accept` widened for the SDK, which otherwise refuses it.

`RequireToken` checks the `Authorization` header against SHA-256 digests of the route's tokens, every one compared in constant time, and hands the token's name to the SDK's bearer middleware as the `TokenInfo` user, where the handlers read it for the audit line.

## Mirror

A `Mirror` registers the downstream catalog on its `*mcp.Server` with `AddTool`, `AddPrompt`, `AddResource` and `AddResourceTemplate`, each with a handler that forwards to the supervisor. Its capabilities are fixed when it is created, from the policy alone, so a client sees the same ones whether or not the server is up.

The sync loop, which runs in the server's `Source`, lists what is marked dirty: everything on each new downstream session (the supervisor's `OnSession` hook), a kind on its list-changed notification. It lists prompts and resources only when some mirror's policy shows them. A failed listing keeps what was there and is retried with backoff; without a session it waits for the next one. The source keeps each listing as the server sent it and hands it to every mirror; a mirror applying a listing compares each entry with the registered one by its JSON encoding and changes only those that differ, so a resync that finds nothing new sends clients no notification. The SDK panics on entries it rejects (a tool schema that is not an object); `validTool` catches the usual case first so the log can say why, and `guard` recovers the rest.

Every tool call, prompt get and resource read runs through the request pipeline ([`pipeline.go`](../../internal/proxy/pipeline.go)), the same for the three kinds, which differ only in their `pipeline` value (the typed request and result, the stages, and whether a failure is answered with a tool result or an error):

| Stage | What it does |
| --- | --- |
| begin | starts the audit record (`Mirror.begin`), counts the call, labels the token policy's decision |
| before forward | the kind's `before` stages in order, each of which may refuse the request or change what is sent: the server's filter (`serverFilter`), then the caller's token policy (`tokenPolicy`), each refusing a hidden entry with the error of an unknown one |
| forward | sends the typed request through the `proxy.Downstream` the source was attached to, with the downstream `_meta` and progress (`forward`) |
| outcome | maps the answer: no session is `unavailable`, an error is rebuilt (`call.downstreamError`), no result or one asking for input fails; a tool call answers the first and the last with a tool result |
| after forward | the kind's `after` stages in order, each of which may change or withhold the result: redaction (`redactWith`), then for a tool call the file scan (`scanFiles`) and the `tool_error` outcome |
| end | hands the audit record to the mirror's sink (`call.end`) |

A refusal or a failure ends the request at its stage, with an outcome that says why. `proxy.Downstream` holds only the typed calls (`CallTool`, `GetPrompt`, `ReadResource`) and the error texts, so the pipeline is tested against a fake without any session; a source is attached to a `proxy.Supervisor`, which adds the session the catalog is listed on.

The forward stage builds the downstream `_meta` (`downstreamMeta`: only the server's `forwardMeta` keys), opens a progress sink when the client asked for progress, and sends the request through the supervisor on the upstream request's context. The progress sink has a gate token (`mcp-gate-<n>`, numbered per source, so the mirrors of one server never share one) that the downstream sees, scrubs messages with the redaction of the call's mirror, keeps only the newest unsent notification and sends it from its own goroutine on the upstream request's `ServerSession`, so a client that does not read blocks only its sink.

Downstream notifications arrive from the SDK one at a time on the session's reader, so the handlers only enqueue (64 deep, counting what they drop) and one worker per source delivers progress and logs the server's log messages, scrubbed by the current mirror.

The redaction stage runs `mcpredact` with the server's engine and the replacer that the server's `proxy.ReplacerFunc` returns for the call: `redact.Marker` by default, the escrow's with the escrow on, or what `gate.Options.Replacer` returns in tests. The function gets a `proxy.Request` with the method, the name and the arguments, which a replacer that keeps values records as the source. Each call counts its findings through a wrapping replacer for its audit record. The file scan stage then runs a redacted tool result through the server's file scanner, if it has one.

A failed call's error is rebuilt by `call.downstreamError`, never passed on: the SDK reports an HTTP request that could not be sent as a JSON-RPC error (`ErrRejected`, code -32005) whose message quotes the full URL, so every message first goes through `HideURL`. A JSON-RPC error keeps its code; its message and, for an unwrapped error reply, its data are then redacted with the call's replacer, or with results not redacted the message goes through `ErrorText` and the data is dropped.

The receiving middleware of a mirror's servers and of a view's is one function, `receiving` ([`refusal.go`](../../internal/proxy/refusal.go)): it recovers panics in request handling, which the SDK runs on goroutines of its own, and hands a tool call, prompt get or resource read that failed without reaching a handler of the gate (a context value tells) to a refusal function. The mirror's audits it with `Mirror.refusedEarly`: every tool call and prompt get the SDK refuses (an unknown or filtered name), and a read only when the caller's token policy hides its URI. The notification worker and the progress sinks recover their own panics.

Token policies are a `policy.Tokens` per mirror (`proxy.Options.Tokens`), built from the config when the mirror is made and never changed. The mirror makes a `*mcp.Server` of its own (`tokenView`) for each token that has one, synced from the mirror's catalog under the mirror's lock after every applied listing, holding only what the policy passes; the route's `getServer` picks it by the `TokenInfo` user (`Mirror.ServerFor`). A hidden entry is therefore unknown to the SDK on that server: lists, pagination cursors, list-changed notifications and the SDK's checks that run before any handler (such as the `Mcp-Param-*` headers of a `2026-07-28` tool call) never see it. The handlers are the mirror's, which check access again with the policy itself (`TokenFilter.Allows`, and for a read the token's `policy.Reads`, compiled from the mirrored resources and templates at each listing) and refuse what it does not pass, whether the mirror holds the name or not. The audit line's `tokenPolicy` labels the decision only for what the mirrored catalog holds; anything else is labelled `none`. When any token has a policy on the server, every one of its servers marks its results `private` through `SetCacheable`.

Policy filters and server filters are distinct types (`policy.TokenFilter` from `NewTokenFilter`, `policy.ServerFilter` from `NewServerToolFilter` and `NewServerFilter`), since an empty allow list means different things in them. Which URIs may be read is decided by one algorithm, `policy.Reads`, compiled once per listing from the catalog: for the server's resource filter (`Policy.SetCatalog`, from everything the server lists) and for each token's (from what the mirror serves). The mirror also compiles, once per listing, what reads reach (`served`: listed URIs, their comparison keys, the templates' patterns). Every refusal of an entry the caller may not see uses `errUnknownTool`, `errUnknownPrompt` or `errUnknownResource`, the SDK's own errors for a missing entry, with the name as the caller wrote it.

## Audit

Every tool call, prompt get and resource read that reaches a mirror's handler, or that the SDK or the aggregate refuses before one, makes one [`audit.Record`](../../internal/audit/audit.go): the server, the token name, the entry's `Kind` (tool, prompt or resource) and its name made fit for the log, the duration, the `Outcome`, the token policy's decision and the number of redactions. The exception is a resource read that the SDK refuses before a handler runs because no server the caller may reach serves its URI: it makes none, unless the caller's token policy hides the URI. A mirror's records all go through `Mirror.emit`, which counts the failed ones (every outcome but `ok` and `tool_error`) for `/_status` and hands them to the mirror's `audit.Sink` (`proxy.Options.Audit`); the aggregate's own refusals go to its sink (`proxy.AggregateOptions.Audit`). Without one set, the sink is `audit.Log`, which writes each record as one `call` line with the attributes in a fixed order; `TestAuditLinesGolden` and `TestAuditOutcomesGolden` pin the exact text. The `Kind` values are bits, and the mirror and the source use them as sets (`kindSet`) for what a listing holds and what a mirror shows.

## Aggregate endpoint

With `aggregate` set, [`gate.aggregateRoute`](../../internal/gate/aggregate.go) mounts `/mcp` through the same `chain` as a server route, with its own token check in place of `RequireToken`:

```
client ─POST /mcp─▶ Recover ─▶ LogRequests ─▶ AllowHosts ─▶ aggregate.authorize ─▶ CrossOriginProtection
   ─▶ held until started or its servers listed (or waiting for a login) ─▶ ReadBody ─▶ respond ─▶ SDK StreamableHTTPHandler (stateless; event stream or JSONResponse)
   ─▶ the View's mcp.Server ─▶ View.receive ─▶ View handler (access checked again) ─▶ Mirror handler
```

`authorize` runs the request's credential through every member's own `upstream.Tokens` (a public member takes any request) and gets the members it reaches, each with the token name it knows. That set, with the name of the token on each member where it has a policy, picks the request's `View`; the tokens and policies of a snapshot do not change, so the views are made when the snapshot is built, one per distinct access. A view takes from each member what the member serves the caller's token (`Mirror.Catalogs`), so token policies are applied in the mirror only; a view with a member on which any token has a policy marks its results `private`, a name it leaves out is refused by the SDK as unknown and audited by its mirror (`Mirror.refused`) with the policy's decision. The access travels to the MCP handlers in `TokenInfo.Extra` (`proxy.AccessInfo`); the request's own header never does.

[`proxy.Aggregate`](../../internal/proxy/aggregate.go) watches the members (`Mirror.Watch`, called after each applied listing) and, on a change, reads their `Catalog` snapshots, names the tools and prompts `<server>__<name>` (dropping names over `config.AggregateMaxName` characters or outside `[A-Za-z0-9_.-]`), and syncs every view with the same `syncSet` the mirror uses, so the SDK tells listening clients what changed. A view registers only its servers' entries, leaving out, and logging once, a resource URI or template that two of them list, and keeps per server the URIs it lists and its compiled templates to route reads.

A view's handler checks that the request's access names the entry's server, then calls that mirror's own handler (`callTool`, `getPrompt`, `readResource`) with the server's own name for the entry and a `TokenInfo` holding the token name that server knows. From there the call is exactly a call on the server's route, audit line included. `View.receive` is `receiving` with the view's refusal function: a name whose server the request reaches is audited by that mirror (`Mirror.refusedEarly`, as on the server's route), a read of a URI no such server serves not at all, and any other tool call or prompt get by the aggregate with an empty `server`.

## Snapshots and reloads

Everything a reload can change is in a [`snapshot`](../../internal/gate/snapshot.go): the config, the enabled servers, each with its `Mirror`, and a `route` per pattern with its handler chain, tokens and, for `/mcp`, the aggregate and its views. A snapshot does not change once `build` has made it. The listener's handler, `serveHTTP`, loads the current one from an atomic pointer and lets its mux pick the route; the route counts the request until it ends, and a route that was retired in between hands the request back to `serveHTTP`, so a request is served by one config from its token check to its audit line.

Three things outlive a snapshot when their inputs are unchanged, and `build` compares keys to keep them:

- A server's `serverRuntime`: its supervisor and its [`proxy.Source`](../../internal/proxy/source.go), which lists the catalog, keeps the last listing before any policy, the counters and the progress table, and runs the notification worker. Kept while `downstreamKey` is unchanged.
- A `Mirror`: the server under one policy, redaction and `forwardMeta`, a projection of its source. `proxy.New` attaches it to the source, which applies what it has listed at once and every later listing; a kind no mirror showed before is listed when a mirror that shows it attaches. Kept while the runtime and `mirrorKey` are unchanged.
- A `route`: kept while its mirrors (by identity) and the config values it was built from are unchanged, so its `subscriptions/listen` streams go on.

A runtime built for a server whose downstream settings changed takes over the old source's listing and counters (`Source.Inherit`), so the server keeps its catalog listed while it restarts, as after a crash.

What a change of each config field does is set in one table, [`configFields` and `serverFields`](../../internal/gate/fields.go): downstream, mirror, route, snapshot, boot or derived. The downstream, mirror and route keys and the boot-only warning are read from it by reflection, and `TestFieldsClassified` fails on a field the table leaves out.

`Gate.notify` sends nothing after `STOPPING=1`. `Gate.Reload` takes `mu`, which orders it with `Run` and the shutdown, and waits for `Run` to have started the servers. `build` either succeeds or closes the mirrors it made, leaving nothing changed. The swap stores the snapshot and retires the routes it replaced: their `ended` channel ends their listen streams, and their `idle` channel closes when their last request ends. A runtime the new snapshot no longer uses is stopped once every retired route that reaches it, from this or an earlier reload, is idle, or after `ShutdownGrace`; new runtimes start after that. When the shutdown begins first, the reload leaves those runtimes to it (`leftover`), which stops them after its own grace. A runtime with the downstream settings of an old process that did not end within `stopTimeout`, whatever its server is now named, is started only once that process has ended, and never once the shutdown has begun (`pendingStop`, `startRuntime`); the old source is closed then. A runtime that replaces one is `restarting` until its server has connected, and its route holds requests meanwhile, as `awaitReady` does during startup. A request that passed a route's token check before the route was retired, and finishes reading its body or being held after, is handed back to `serveHTTP` with its body, the context it arrived with and the client's `Authorization` header, so the current snapshot checks it again from scratch; `upstream.MarkHandedOn` marks the first route's request line. A held request is refused as soon as the shutdown begins. A replaced mirror is closed once the retired routes are idle, or once the shutdown has drained the listener. Kept supervisors get the new redaction engine for their errors and stderr (`SetRedactor`). The shutdown cancels `retireCtx` first, so it never waits out a reload's grace. `check` builds the gate with `gate.New`, starting nothing, so it refuses what a reload would.

## Listener and restarts

`mcp-gate serve` asks [`systemd.Listener`](../../internal/systemd/systemd.go) for a socket passed in `LISTEN_FDS` (checked against `LISTEN_PID`) and only without one calls `Gate.Listen`, which opens `listen.addr`; `Gate.Run` serves whichever listener it is given. `net.FileListener` duplicates the passed descriptor close-on-exec, and `childEnviron` drops the `LISTEN_*` and `NOTIFY_SOCKET` variables, so no stdio child inherits either. `Options.Notify` receives `READY=1` when `awaitStartup` marks the gate started and `STOPPING=1` when the shutdown begins; the command sends them to `NOTIFY_SOCKET` with a `systemd.Notifier`.

A restart under systemd is a plain stop and start: no descriptor is handed from one process to the next. The socket systemd holds outlives both, and connections queue in it while neither accepts. What makes that invisible to clients is in three places. The upstream handler is stateless, so the new process accepts any client's next request as it would have the old one's. `chain` holds a request whose server is not mounted while the gate starts (`awaitReady`, polling every 100 ms until the startup watcher closes `startupOver`), so the queued requests are answered once their server is back rather than refused with 503. And the shutdown drains connections before closing them (below).

## Shutdown

`shutdown` begins with `upstream.Server.Drain`: it closes the listeners and, for up to `drainLinger` (1 second), keeps serving the requests that arrive on connections already open, with `Connection: close` on every response whose header is written from then on (`closingWriter`, which also covers a call that began before). It returns as soon as every open connection is closing after its response. Without it, `Shutdown` would close idle kept-alive connections at once, and a request a client sent on one at that moment would fail with a reset or EOF; HTTP clients retry that only for idempotent requests, which an MCP POST is not. Only connections left idle for the whole linger are then closed under a client; so is the connection of a `subscriptions/listen` stream, whose header was written before the drain and which goes back to idle when the drain ends the stream.

`http.Server.Shutdown` waits for every open request, and a `2026-07-28` client listening for changes keeps one POST open for good. `respond` recognises `subscriptions/listen` bodies and ties their context to a channel closed when the shutdown begins, so those streams end at once and only real calls use the 10 second grace. `Shutdown` also waits until a connection on which no request has arrived is 5 seconds old, and HTTP clients keep spare connections they may never use: `upstream.NewServer` tracks those through `ConnState` and closes them from `RegisterOnShutdown`. That tracking is why the listener serves HTTP/1 only: net/http does not report an HTTP/2 connection becoming active.

`upstream.NewServer` also wraps the handler in `BoundWrites`. There is no `WriteTimeout`, which would bound the whole response and so a long call; instead each write, cut into 64 KiB pieces, and each flush gets a write deadline 30 seconds out, so a client that takes in less than 64 KiB in 30 seconds, about 2 KiB/s, is cut off. A write that stalls fails; net/http then closes the connection and cancels the request's context, which ends the call and the progress sink behind it. The deadline is cleared when a request starts, so that one left by the previous request on the connection cannot fail an early write such as `100 Continue`, and set again when the handler returns, for net/http's final flush. An idle stream (a `subscriptions/listen` POST) is unaffected: the deadline is set before each write, not between them.
 The mirrors run on a context detached from the signal, so calls finishing in the grace still get their progress; `shutdown` closes them after stopping the servers. A server that does not stop in time is logged and does not change the exit status.

## Readiness and status

`Gate.Run` starts every supervisor and mirror, then serves. A watcher marks the gate started once every mirror has listed its catalog or its supervisor waits for an OAuth login, or when `startupGracePeriod` ends. `/_readyz` reads `Gate.Readiness`: a server counts as mounted once its catalog was listed, as unhealthy while mounted and in a state other than `ready` or `degraded`, and as needing a login while its supervisor is `needs-login`, mounted or not. `DownstreamOptions` gives an OAuth server a `Source` over the store in the state directory. `/_status` merges `Supervisor.Status` with `Mirror.Stats`, and reads the child's resident memory from `/proc/<pid>/statm`.

## Learned pins

The supervisor reports an automatic protocol pin through `OnPinLearned`. The gate writes all pins to `pins.json` in the state directory (temporary file, sync, rename) and passes each to its supervisor as `LearnedPin` at the next start.
