# approvals

[Docs](../README.md) / [Commands](README.md) / **approvals**

`mcp-gate approvals` lists and decides the tool calls a running gate holds for the owner's approval (see [serve](serve.md#approvals)). It talks to the gate's `/_approvals` endpoint over HTTP with an admin token; the specification is [`openspec/specs/approvals/spec.md`](../../openspec/specs/approvals/spec.md).

```console
$ export MCP_GATE_ADMIN_TOKEN=…        # one of admin.tokens
$ mcp-gate approvals list
3f2a9c0d11e4b5a7  chat/send_message  by laptop  4m12s left
  {"chat":"team","text":"Deploy is done, token [REDACTED:github_token]"}
$ mcp-gate approvals approve 3f2a9c0d11e4b5a7
3f2a9c0d11e4b5a7: approved
$ mcp-gate approvals deny 3f2a9c0d11e4b5a7
mcp-gate approvals: no pending approval 3f2a9c0d11e4b5a7: it was decided, it expired, or the id is wrong
```

`list` shows each pending approval, oldest first: its identifier, the server and tool, the token that made the call (`(no token)` on a public server), the time left, and the arguments: redacted, with control, format and bidirectional characters written as `\uXXXX` so they cannot drive the terminal, and long values cut, which the line marks with `(cut; <size> bytes forwarded)`. `approve` lets the call go to its server; `deny` answers it with a tool error. Each approval is decided once; the audit line names the admin token that decided it.

| Setting | Default | Meaning |
| --- | --- | --- |
| `-url` | `$MCP_GATE_URL`, else `http://127.0.0.1:9090` | The gate's base URL, the `listen.addr` it serves |
| `MCP_GATE_ADMIN_TOKEN` | required | An `admin.tokens` value. It is read from the environment only, so it never shows in the process list |

The gate needs `admin.tokens`; without them `/_approvals` is 404. The endpoints are plain HTTP and can be called directly too:

```console
$ curl -s -H "Authorization: Bearer $MCP_GATE_ADMIN_TOKEN" http://127.0.0.1:9090/_approvals
{"pending":[{"id":"3f2a9c0d11e4b5a7","server":"chat","tool":"send_message","principal":"laptop","arguments":"…","size":61,"truncated":false,"created":"2026-01-02T10:00:00Z","expires":"2026-01-02T10:05:00Z"}]}
$ curl -s -X POST -H "Authorization: Bearer $MCP_GATE_ADMIN_TOKEN" http://127.0.0.1:9090/_approvals/3f2a9c0d11e4b5a7/approve
{"id":"3f2a9c0d11e4b5a7","approval":"approved"}
```

Exit status: 0 done; 2 otherwise, an identifier that is no longer pending included.
