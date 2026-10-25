# Escrow and file scanning

[Docs](../README.md) / [Architecture](README.md) / **Escrow and file scanning**

The escrow keeps redacted secrets in memory so that the owner can release them, and file scanning withholds downloaded files that hold secrets. The behaviour is specified in [`openspec/specs/escrow/spec.md`](../../openspec/specs/escrow/spec.md) and [`openspec/specs/file-scanning/spec.md`](../../openspec/specs/file-scanning/spec.md).

## Packages

| Package | Contents |
| --- | --- |
| [`internal/escrow`](../../internal/escrow/escrow.go) | The store, the replacer that keeps findings, kept files, the HTTP API and its failed-auth limit. No MCP imports |
| [`internal/filescan`](../../internal/filescan/filescan.go) | Finds the paths a file tool's call names, opens them safely, scans them with the redaction engine, and withholds them from the result |
| [`internal/testkit`](../../internal/testkit/escrow.go) | `CheckEscrowContract`, the HTTP contract as a test, run against the bare handler and against a running gate |

## Wiring

`cmd/mcp-gate serve` reads `MCP_HUB_ESCROW_KEY_SHA256` and passes the decoded hash as `gate.Options.EscrowKeyHash`. `gate.New` then builds one `escrow.Escrow` and mounts its handler at `/_escrow/` on the listener's mux, wrapped only in `upstream.Recover`: the Host check, the tokens and the filters of the MCP routes are not in its chain. The escrow gets the listener's `RemoteFunc`, the same that the request log uses, so behind a proxy its client address is the right-most `X-Forwarded-For` entry outside `trustedProxies`. `Gate.Run` runs the sweep loop until shutdown.

Each server's `proxy.Redaction` gets a `proxy.ReplacerFunc`: for every call the mirror builds a `proxy.Request` (method, name, and the arguments decoded once, lazily) and asks for a replacer, which with the escrow on is `Escrow.Replacer` with the server's name and `redact.escrowTTL`. Progress messages and logged texts use `redact.Marker` directly, so they never create entries.

A server with `redact.files` gets a `filescan.Scanner` as `proxy.Options.Files`, with `Escrow.KeepFile` as its keeper when the escrow is on. `Mirror.callTool` runs it on the redacted result, with the time taken just before the call was forwarded; an error withholds the result like a redaction failure, and the number of withheld files is added to the audit line's redactions.

## Store

`store` is a map from handle to entry under one mutex, plus a map from a dedup key (server, kind, SHA-256 of the value) to handle. Eviction scans for the oldest entry, which is linear in the entries; `escrow.maxEntries` is capped at 100000 to keep that cheap. Values are cleared with `clear` when an entry goes, as a best effort. File entries hold no content: they record the resolved root, the path below it, the size and the SHA-256, and `readFile` opens the root again with `os.OpenRoot`, opens the file with `O_NOFOLLOW|O_NONBLOCK`, and serves it only if it still matches.

## Failed-auth limit

`limiter` keeps a token bucket per client (an IPv6 address counts by its /64): 20 tokens, one more every 3 seconds, and a presented wrong key spends one. A request without a key costs nothing, so a web page that fires requests at a local listener cannot lock the owner out. A client with less than one token gets 429 before its key is looked at, so that a lucky guess is refused too. The table holds at most 4096 clients; a new one replaces the bucket with the most tokens, so a client that never failed is never in it. A client that rotates addresses gets a fresh budget with each one; the limit slows guessing and keeps the log readable, while the key's length is what protects it. Behind a proxy on loopback, every local process can name its own address in `X-Forwarded-For`; keep agents off the trusted peer, or narrow `trustedProxies` to the proxy's own address. Devices that share an IPv6 /64, such as a home LAN, share one budget.

## File scanning

`candidates` (at most 64 per call) walks the structured content, JSON text content and the arguments for path members, takes `file://` URIs and resource URIs, and matches "downloaded to" in text. `Scanner.open` resolves symlinks with `filepath.EvalSymlinks`, finds the root that contains the result (roots are resolved on every call, so a download directory created after the start works), opens it through `os.Root` and checks the opened file: regular, one link, inode change time (`ctime`, which a writer cannot set) at or after the call. `Scanner.scan` reads at most `maxBytes` into memory, two scans at a time process-wide, hashes it, and runs `Engine.RedactString` with a replacer that only records kinds. `withhold` copies what it changes, so the downstream's result is never modified.

The platform-specific part, the link count and the inode change time, is in `stat_linux.go` and `stat_darwin.go`.
