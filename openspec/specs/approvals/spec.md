# approvals Specification

## Purpose

The owner can make chosen tool calls wait for their approval before the gate forwards them, such as `send_message`, `delete_*` or `checkout`. A held call is announced to the owner through a webhook, with its arguments redacted, and decided with `mcp-gate approvals` or with one-time links the webhook carries. A call that nobody approves in time is not forwarded. Pending approvals live in the gate's memory only.

## Requirements

### Requirement: Approval rules

A server MAY set `approve`, and a token's policy on a server (`policies.<token>.servers.<server>`) MAY set `approve` too: each a list of tool name patterns, where a pattern is a tool's name, or ends in `*` and matches every name that starts with what comes before it (`*` alone matches every tool). A tool call SHALL be held for approval when its name, as the server names the tool, matches a pattern of the server's list or of the caller's token's list on the server; a token's list SHALL only add to the server's. Prompt gets and resource reads SHALL never be held. The rules SHALL apply alike on the server's route and on the aggregate endpoint.

Approval SHALL be the last stage of the request pipeline before the call is forwarded: every other check that may refuse the call, today the server's filter and the token's policy, SHALL run before it, and so SHALL any check added to the pipeline later, such as a rate limit or a check of the arguments, so that the owner is asked only about a call the gate would otherwise forward. A call of a tool the server's filter or the token's policy hides SHALL fail as one of an unknown tool, without being held or announced, so that a hidden tool stays indistinguishable from a missing one.

#### Scenario: Pattern and token list

- **WHEN** a server sets `approve: [send_message, "delete_*"]` and the token `phone` has `approve: [echo]` in its policy on it
- **THEN** calls of `send_message` and `delete_item` are held for every token, `echo` is held for `phone` only, and `env` is forwarded at once for every token

#### Scenario: Hidden tool is not held

- **WHEN** `phone`'s policy on the server hides `send_message`, which the server's `approve` names, and `phone` calls it
- **THEN** the call fails exactly as a call of a tool the server does not have, nothing is announced or listed as pending, and the audit line has outcome `denied` and no `approval`

### Requirement: Holding a call

A held call SHALL become a pending approval with a random identifier of 16 lower-case hex digits and, when `approvals.webhook.linkURL` is set, a random link token of 256 bits. It SHALL wait until it is decided, for at most `approvals.timeout` (default `5m`). The call SHALL be forwarded only when it is approved; denied, it SHALL be answered with a tool result with `isError` and the text `mcp-gate: the owner did not approve this call of <tool>`, and expired with `mcp-gate: the owner did not answer the approval request for <tool> in time`, `<tool>` being the name the caller used. A call whose client gives up while it waits SHALL end without being forwarded, and its pending approval SHALL be dropped. A decision SHALL be final: a pending approval SHALL be decided once, and deciding it again, or one that has expired, SHALL find no pending approval. At most 64 calls SHALL wait at a time; one more SHALL be denied at once by `gate`.

While a call waits and its request carries a progress token, the gate SHALL send it a progress notification every 10 seconds, with a progress that grows by one each time and the message `waiting for the owner's approval (<id>)`, so that a client whose request timeout restarts on progress keeps waiting.

Pending approvals SHALL NOT outlive the configuration they were asked under: a reload that applies a config SHALL deny every pending approval, and so SHALL the beginning of the shutdown, both by `gate`; a call held during the shutdown SHALL be denied at once by `gate`. A restart therefore denies them too.

#### Scenario: Approved call

- **WHEN** a held call of `send_message` is approved with `mcp-gate approvals approve <id>` by the admin token `owner`
- **THEN** the call is forwarded and answered with the server's result, and the audit line has the call's outcome, `approval` `approved` and `approver` `owner`

#### Scenario: Timeout

- **WHEN** nobody decides a held call within `approvals.timeout`
- **THEN** the call is answered with the expired tool error, the server never sees it, it is no longer listed as pending, and the audit line has outcome `not_approved` and `approval` `expired`

#### Scenario: Reload while waiting

- **WHEN** a reload applies a config while a call waits for approval
- **THEN** the call is answered with the denied tool error, and the audit line has `approval` `denied` and `approver` `gate`

#### Scenario: Progress while waiting

- **WHEN** a held call carries a progress token and waits 25 seconds before it is approved
- **THEN** the client gets two progress notifications with progress 1 and 2 and the message `waiting for the owner's approval (<id>)` before the result

### Requirement: Notice

The config MAY set `approvals.webhook` with `url`, the endpoint each pending approval is announced to. For each held call the gate SHALL send it one `POST` with `Content-Type: application/json` and a JSON object with `id`, `server`, `tool` (the server's name for it), `principal` (the token's name, empty on a public server), `arguments`, `created` and `expires` (RFC 3339 times, UTC), and, when `approvals.webhook.linkURL` is set, `approveURL` and `denyURL` (see Deciding). `arguments` SHALL be the call's arguments as JSON text, redacted with the server's redaction rules, or with the default rules on a server whose results are not redacted, findings replaced by `[REDACTED:<kind>]` and never kept in the escrow, cut at 4096 bytes; arguments that cannot be redacted SHALL be replaced by `(the arguments could not be redacted)`. With `approvals.webhook.secret` set, the request SHALL carry `X-Mcp-Gate-Signature: sha256=<hex>`, the HMAC-SHA256 of the body with the secret as its key.

The notice SHALL be sent while the call waits, without delaying it, and SHALL take at most 10 seconds. A redirect SHALL NOT be followed. A connection to a link-local address or a cloud metadata address SHALL be refused. A notice that fails or is answered with a status other than 2xx SHALL be logged as a warning that names the server, the tool and the status or the cause, never the URL; the call SHALL go on waiting, since it can still be decided with `mcp-gate approvals`.

#### Scenario: Redacted and signed notice

- **WHEN** a held call has the argument `{"text": "password: hunter2hunter2"}` and `approvals.webhook.secret` is set
- **THEN** the webhook gets `arguments` with `[REDACTED:password]` and not the password, and a signature that the secret verifies

#### Scenario: Webhook down

- **WHEN** the webhook answers 500
- **THEN** the gate logs a warning without the URL, and the call is still listed by `mcp-gate approvals list` and can be approved

### Requirement: Deciding

With `admin.tokens` set, the listener SHALL serve, to requests carrying an admin token as `/_status` takes it (others SHALL get 401):

- `GET /_approvals`: `{"pending": [...]}`, the pending approvals, oldest first, each with `id`, `server`, `tool`, `principal`, `arguments`, `created` and `expires` as in the notice;
- `POST /_approvals/<id>/approve` and `POST /_approvals/<id>/deny`: decide the pending approval and answer 200 with `{"id": "<id>", "approval": "approved"}` or `"denied"`, the admin token's name being the approver; 404 when no pending approval has that identifier.

With `approvals.webhook.linkURL` set, the base URL at which relays reach the gate, the notice's `approveURL` and `denyURL` SHALL be `<linkURL>/_approvals/link/<token>/approve` and `…/deny`, and the listener SHALL serve `POST` to them without a token, deciding the pending approval with the approver `link` and answering 200 with the same body; 404 for a token that matches no pending approval. A link SHALL decide once. Any other method SHALL get 405, so that a link preview or a crawler that fetches the URL decides nothing. Without `linkURL` the link paths SHALL be 404. Every answer of these endpoints SHALL carry `Cache-Control: no-store`.

`mcp-gate approvals list`, `mcp-gate approvals approve <id>` and `mcp-gate approvals deny <id>` SHALL call these endpoints of a running gate at `-url` (default `MCP_GATE_URL`, else `http://127.0.0.1:9090`), with the admin token from `MCP_GATE_ADMIN_TOKEN`, which SHALL be required and never taken as an argument. `list` SHALL print one line per pending approval with its identifier, server, tool, principal and the time left, followed by its arguments, or `no pending approvals`. They SHALL exit with 0 on success and 2 otherwise, a missing identifier included.

#### Scenario: Link decides once

- **WHEN** a relay `POST`s the notice's `approveURL`, and then `POST`s its `denyURL`
- **THEN** the first answer is 200 with `approved` and the call is forwarded, the second is 404, a `GET` of either is 405, and the audit line has `approver` `link`

#### Scenario: Without an admin token

- **WHEN** `GET /_approvals` or `POST /_approvals/<id>/approve` carries no admin token
- **THEN** the answer is 401 and the call keeps waiting

### Requirement: Audit

The `call` line of a held call SHALL carry, after `redactions`, `approval`, which is `approved`, `denied`, `expired` or `cancelled` (the client gave up), and, for `approved` and `denied`, `approver`: the admin token's name, `link`, or `gate`. A denied or expired call SHALL have the outcome `not_approved`, and a cancelled one `error`; an approved call SHALL have the outcome of its forwarding. The line of a call that was not held SHALL carry neither attribute.

#### Scenario: Denied call in the audit line

- **WHEN** the admin token `owner` denies a held call of `send_message`
- **THEN** its `call` line has outcome `not_approved`, `approval` `denied` and `approver` `owner`, and `mcp_gate_requests_total` counts it with outcome `not_approved`

### Requirement: Approval keys

The config MAY set `approvals.timeout` (between `1s` and `1h`, default `5m`) and `approvals.webhook` with a required `url`, an optional `secret` of at least 16 characters and an optional `linkURL`. `url` and `linkURL` SHALL be absolute URLs that are `https`, or `http` on a loopback address or `localhost`, without user information, a query or a fragment, since the notice carries the link tokens. Each `approve` list SHALL hold non-empty, distinct patterns without surrounding space, with `*` only at the end, and a token's patterns SHALL NOT start with the server's name and `__`. A config with any `approve` list SHALL set `admin.tokens` or `approvals.webhook.linkURL`, so that someone can decide. A token policy on a server SHALL set at least one of `tools`, `prompts`, `resources` and `approve`.

#### Scenario: Nobody can decide

- **WHEN** a server sets `approve` and the config has neither `admin.tokens` nor `approvals.webhook.linkURL`
- **THEN** loading fails naming `servers.<name>.approve`
