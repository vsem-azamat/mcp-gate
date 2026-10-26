# aggregate-endpoint Specification

## Purpose

With `aggregate` set, the gate also serves many servers together at `/mcp`. A request reaches exactly the members whose own routes would take it (the public members, and those that accept its token), and is served a catalog of only those members, under the token's policies, with tools and prompts named `<server>__<name>`. Each call is handled by its member as on the member's own route.

## Requirements

### Requirement: Aggregate endpoint

With `aggregate` set, the gate SHALL also serve the servers of `aggregate.servers` (every enabled server by default) together at exactly `/mcp`, which no server route can be, through the same chain as a server route with these differences. A request SHALL reach a member exactly when that member's own route would accept its `Authorization` header: a public member always, any other when the token is one the member accepts. A request without the header SHALL reach the public members; a request whose credential no member accepts, or that reaches no member, SHALL get 401 with the body `Unauthorized`, even when there are public members. A request that arrives before startup is over (see Health in the gate-lifecycle spec) SHALL be held until every member it reaches has had its catalog listed or is in `needs-login`, or startup ends, and then served.

A request SHALL be served a catalog of only the members it reaches, computed for that set of members and the token's policies on them: each member's tools and prompts as the member's own route lists them to the token, renamed `<server>__<name>`, and its resources and resource templates with their URIs unchanged. A tool or prompt whose new name is longer than 64 characters or holds a character other than ASCII letters, digits, `_`, `.` and `-` SHALL be left out of it and logged once, and a call of it SHALL be refused with a `denied` line naming the member. A resource URI, or a resource template, that more than one of those members lists SHALL be left out of it and logged once, counting entries the token's policy hides. A read SHALL be routed as for a token without a policy, so that a policy changes no read's member. A resource read SHALL go to the one member that lists the URI, or, when none lists it, to the one member with a template that matches it; when no member or more than one qualifies, the read SHALL fail as one of an unknown resource. The upstream server SHALL advertise tools, and prompts and resources when any of the members' does, each with list-changed notifications, and SHALL report the config's `name` and the gate's version as its implementation.

A tool call, prompt get or resource read SHALL be checked again against the access of the request before it is handed to the member, and SHALL then be handled by the member as on its own route: its filters, the token's policy, `forwardMeta`, `callTimeout`, progress, cancellation, redaction, file scanning and escrow, its errors, and its audit line, which SHALL name the member as `server`, the member's own name for the tool or prompt, and as `principal` the name the member gives the token. A request the aggregate refuses before a member sees it, because it names no member the request reaches or is a read that more than one member's templates match, SHALL be logged, with the name redacted under every redaction rule, as a `call` line with outcome `denied`, `tokenPolicy` `none`, an empty `server`, the name as the client sent it, and the request's token names joined by commas as `principal`. A change in a member's catalog SHALL reach the aggregate catalog, and clients that listen for changes there SHALL be told. A member keeps its entries in the aggregate catalog while it is down, as on its own route, and a member whose catalog was never listed has none. `/_readyz` and `/_status` SHALL NOT report the aggregate endpoint. `aggregate.log.requests` SHALL log the requests to `/mcp` as `log.requests` does for a server, naming `/mcp` as the server.

#### Scenario: Tokens with different access

- **WHEN** `alpha` takes the global token `laptop`, `beta` only its own token `phone`, `pub` is public with the tool allow list `[echo]`, and all three are on the aggregate endpoint
- **THEN** `laptop` lists and calls the tools of `alpha` and `pub`, `phone` those of `beta` and `pub`, a request without a token only `pub__echo`; a call of `beta__echo` with `laptop` or of `alpha__echo` with `phone` fails as one of an unknown tool and is logged `denied` with an empty `server`; `pub__sleep` is refused by `pub`'s filter with a `denied` line naming `pub`; and a wrong token gets 401

#### Scenario: Same behaviour as the server's route

- **WHEN** a client calls `alpha__echo` with a GitHub token in the text, `alpha__badblob`, and `alpha__progress` with a progress token, through the aggregate endpoint
- **THEN** the token is replaced by `[REDACTED:github_token]` and the audit line names `alpha` and counts one redaction, the blob result is withheld, and the progress reaches the client

#### Scenario: Catalog change and a long name

- **WHEN** a member adds the tool `fresh` and a tool whose prefixed name is 65 characters long
- **THEN** a `2026-07-28` client listening on `/mcp` is notified, `alpha__fresh` is listed and can be called, and the long tool is listed only on the member's own route

#### Scenario: Resource on two members

- **WHEN** two members both list `fake://info` and the template `fake://items/{id}`
- **THEN** the aggregate catalog lists neither, and reads of `fake://info` and `fake://items/7` fail
