# token-policies Specification

## Purpose

A token's policy (`policies.<token>.servers.<server>`) narrows what the token sees and reaches on a server, on top of the server's own filters: its tools, prompts and resources, on the server's route and on `/mcp`. A hidden tool or prompt cannot be told from a missing one.

## Requirements

### Requirement: Token policies

A token with a policy on a server (`policies.<token>.servers.<server>`) SHALL see and reach only what both the server's filters and the policy's pass. The policy's filters SHALL be matched as a server's filters of the same kind, and `none` SHALL hide every entry of its kind; a filter the policy leaves out, and a server it does not name, SHALL narrow nothing. The token SHALL be served an upstream server of its own holding only what the policy passes, so that its lists, their pagination, list-changed notifications and every check the SDK makes before a handler know nothing of a hidden entry. On a server where any token has a policy, results SHALL carry the cache scope `private`, on the aggregate endpoint too. A tool call or prompt get of an entry the policy hides SHALL fail with the error of a name the server does not have, so that a token cannot tell a hidden tool or prompt from a missing one, and a resource read of a URI the policy does not pass with the error of an unknown resource. A hidden resource is not as well hidden: when a template the policy passes also matches its URI, its read fails while other URIs through that template succeed, so its URI can be found by guessing. A read SHALL pass when the resource the server lists under its URI passes, or, when none is listed, under an allow list a template that matches it passes and under a deny list no template that matches it is hidden; it SHALL also be refused when the comparison key of its URI (see Filters in the serving spec) is that of a listed resource the policy hides or, under a deny list, of an entry the list names. Such a refused read SHALL be logged like a refused call, whereas a read of a URI the server does not serve is not logged. The `tokenPolicy` of an audit line SHALL be `none` for a name the mirrored catalog does not hold or a URI it does not serve in any spelling, such as one the server's own filter hides, since no policy decided it. The capabilities a server advertises SHALL NOT depend on the token. The policy SHALL apply alike on the server's route and on the aggregate endpoint, under the name the server gives the token.

#### Scenario: Tool lists per token

- **WHEN** the global tokens `laptop` and `phone` reach a server, and `phone` has the policy `tools: {allow: [echo]}`, `prompts: none` and `resources: {allow: [fake://info, items]}` on it
- **THEN** `laptop` lists every tool, prompt, resource and template of the server; `phone` lists only `echo`, no prompts, `fake://info` and the template `items`, and reads `fake://items/7`; both lists carry the cache scope `private`, while those of a server without policies carry `public`

#### Scenario: Hidden entry like an unknown one

- **WHEN** `phone` of the scenario above calls `env`, gets the prompt `greet` or reads `fake://hidden`, all of which the server serves
- **THEN** each fails exactly as a call of a tool, a get of a prompt or a read of a resource the server does not have, also for a `2026-07-28` call of a hidden tool with a header-bound parameter, and is logged with outcome `denied` and `tokenPolicy` `deny`, while a call of `nosuch`, or of a tool the server's own filter hides, is logged `denied` with `tokenPolicy` `none`

#### Scenario: Token policy on the aggregate endpoint

- **WHEN** `phone` has the policy `tools: {deny: [env]}` on `plain`, a member of the aggregate endpoint
- **THEN** `phone` does not list `plain__env` there and its call fails as one of `plain__nosuch`, logged with `server` `plain`, outcome `denied` and `tokenPolicy` `deny`, while `laptop` lists and calls it
