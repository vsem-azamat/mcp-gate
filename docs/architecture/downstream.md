# Downstream servers

[Docs](../README.md) / [Architecture](README.md) / **Downstream servers**

How mcp-gate connects to the MCP servers behind it. The behaviour is specified in [`openspec/specs/downstream-lifecycle/spec.md`](../../openspec/specs/downstream-lifecycle/spec.md). `mcp-gate serve` runs one supervisor per enabled server (see [Serving](serving.md)); `mcp-gate check -connect` runs them to try a config.

## Packages

| Package | Contents |
| --- | --- |
| [`internal/downstream`](../../internal/downstream/supervisor.go) | `Supervisor`: states, connect, probes, restarts; the stdio line connection; the size-limited HTTP client |
| [`internal/procutil`](../../internal/procutil/process.go) | Child processes: clean environment, process groups, OOM score, stderr line log, non-dumpable gate, subreaper |
| [`internal/config`](../../internal/config/config.go) | The config file, which `cmd/mcp-gate` turns into supervisor options |

## Supervisor

`downstream.New(opts)` builds a supervisor and `Start` runs its loop in one goroutine: connect, watch the session, tear it down, wait in backoff, connect again. Callers use `Call(ctx, fn)`, which hands `fn` the current `*mcp.ClientSession` and counts the call as in flight; `Status` and `Wait` report the state. `Stop` ends the loop and the child and cancels the calls in flight, since closing a session waits for them.

`Options.Notifications` holds the handlers for the server's progress, log messages and list changes, which the SDK calls one at a time on the session's reader, and `OnSession` is called with each new session once it is ready. On `2026-07-28` sessions the SDK opens `subscriptions/listen` for the list changes it has handlers for, but does not wait for the answer, so a server that rejects it would never report a change. A receiving middleware records the session whose server sent `notifications/subscriptions/acknowledged`; until then, every successful probe calls the list-changed handlers, and the mirror lists again.

Connecting builds a fresh transport each time. Without a pin, the handshake runs under a 5 s sub-deadline: the SDK client sends `server/discover` first and falls back to `initialize` only on an error reply, so a server that ignores discover would otherwise block until the connect timeout (60 s) and then fail. When the sub-deadline expires, the attempt is torn down and repeated offering `2025-11-25`. Silence alone cannot tell a server that ignores discover from one that is slow to start (a cold `npx` cache), so the pin is kept for later connects, and reported through `OnPinLearned`, only when the pinned handshake completes within the sub-deadline; otherwise the next connect tries discover again.

The watch loop wakes on the child's exit, on the session ending (`ClientSession.Wait`), on `Stop` and on the probe ticker. A probe is skipped while a call is in flight and ignored when a call started during it, because single-threaded servers cannot answer a ping while they work. Only failures that are not JSON-RPC error replies count; the SDK reports transient HTTP statuses such as 503 as code -32005, which counts as a failure. The third failure in a row closes the session, but only with no call in flight.

## Stdio

The gate does not use the SDK's `CommandTransport`, which signals only the leader and ends the connection on a frame over 16 MiB. `procutil.Start` creates the pipes itself and starts the command with `Setpgid`, so the child leads a process group, and hands the child its ends as files: `cmd.Wait` then never waits for copying goroutines, and the group can be killed as a whole. `Stop` closes stdin, sends SIGTERM to the group, polls until the leader is reaped and `kill(-pgid, 0)` reports the group empty, then repeats with SIGKILL. On Linux a zombie member keeps the group from being empty until it is reaped; on darwin `kill(-pgid, 0)` skips zombies and fails with `EPERM` when only they are left, so `Stop` can return while a grandchild left to `launchd` is still a zombie. Once the leader is reaped and the group is empty, its PID may be reused, so no further signal is sent to it. Members reparented to the gate are reaped with `wait4(-pgid)` once the leader is gone.

`lineConn` implements `mcp.Connection` on the pipes. It reads frames with a `bufio.Reader`; a frame over `maxMessageBytes` is consumed to its newline, keeping only its first and last kilobyte. The id is taken from either end, since most servers write it first and the TypeScript SDK last. When the head shows a response (a top-level `result` or `error` before any `method`, so that a request from the server with a colliding id is never taken for one) and the id names a request the gate sent that is still pending, a JSON-RPC error response is delivered in place of the frame. An id is dropped from the pending set when its response arrives or its cancellation is sent. A dropped response whose id cannot be found leaves its call waiting until `callTimeout`; with `callTimeout: 0s` that call, and the probes it suspends, wait for good. Lines that do not decode are skipped.

`procutil.EnableSubreaper` sets `PR_SET_CHILD_SUBREAPER` and reaps, on SIGCHLD and every second, zombie children that `Start` did not create (orphans that left the group with `setsid`). Every child of the gate must therefore be started through `procutil.Start`. `procutil.SetNonDumpable` clears the dumpable flag, so same-user processes cannot read the gate's memory or environment. Both are Linux only, as is `oom_score_adj`; elsewhere they do nothing. `Start` returns once the child's close-on-exec files are closed, which the kernel does before it makes the new program dumpable again, so for a moment the files under `/proc/<pid>` belong to root; opening `oom_score_adj` is therefore retried for up to 500 ms while it fails with `EACCES` or `EPERM`. A write refused once the file is open (a score below the child's `oom_score_adj_min`) is not retried. A failure that remains is logged.

Errors kept in the status and logged go through `Supervisor.ErrorText`, which replaces the server's URL (Go's HTTP errors quote it whole) with `<servers.NAME.http.url>` (`Supervisor.HideURL`) before redacting, and cuts at a character boundary (`redact.Cut`).

Child stderr goes through a `LineLog`: up to 8 KiB of each line is read and redacted (minus a margin at the cut, so a secret across it is not half kept), then cut at 4 KiB, logged under a rate limit (20 lines a second, bursts of 100) and kept in a 64 KiB ring that outlives restarts. Each kept line wakes `Wait`, since the ring is part of `Status`.

## HTTP

The SDK's streamable client transport gets an `http.Client` whose transport wraps a clone of the default one. It adds the configured headers, follows no redirects, and limits responses:

- an error response body is cut at 64 KiB;
- a JSON body is read into memory up to `maxMessageBytes`; a larger one (or a larger `Content-Length`) is replaced by a JSON-RPC error for the request id found in the POST body, which is decoded only then, so the SDK fails only that call instead of the connection;
- an event stream passes through one event at a time; an event over the limit is dropped and, when it is the response to the call that opened the stream, replaced by an error event. The SDK's own `MaxEventSize` is set slightly higher, as a backstop.

Compressed responses are decoded by the Go transport before the limits apply; `Accept-Encoding` cannot be configured.

A server with an `oauth` block gets an `oauth.Source` as the transport's `OAuthHandler` (see [OAuth](oauth.md)). Before each connect the supervisor asks it for a usable grant; without one, the connect fails with a `LoginRequiredError`, the state becomes `needs-login`, the error is logged once, and the loop keeps trying after the backoff without counting restarts or leaving `needs-login` while the grant is unusable. A call that fails while the grant is unusable kicks the watch loop into a probe once the call has ended, and a failed probe with the grant unusable closes the session at once.
