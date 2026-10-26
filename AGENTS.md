# mcp-gate Agent Instructions

This file is the working contract for AI agents and contributors in this repository. It says how to work and where to look; facts about the project live in [`docs/`](docs/README.md).

## Setup

Run `make hooks` once after cloning, so the versioned git hooks in `.githooks/` run on commit and push. Never bypass them with `--no-verify`; fix what they report.

Git worktrees live in `.worktrees/<name>` inside the repository (git ignores it), never next to it.

## Sources Of Truth

- Behavior specifications go in `openspec/specs/`. Once a capability is specified there, read it before changing that behavior.
- `docs/` describes how mcp-gate is built and checked. Start at [`docs/README.md`](docs/README.md).
- Code is the source of truth for how something is implemented. If code and a spec disagree, stop and reconcile them.

## Current State Only

- Everything in the repository is written in English.
- Specs and docs describe the system as it is now: no history, decision logs, plans, roadmaps or status notes.
- A behavior change adds or edits its spec in `openspec/specs/` in the same PR as the tests and code that implement it. A PR that changes only specs may reword them but not change behavior. `openspec/changes/` is never committed.
- Rationale belongs in the PR description; deferred work belongs in an issue.
- Do not commit scratch files, agent plans, handoff notes, logs or temporary output.

## Public Repository Hygiene

This repository is public. Before every commit and PR, check that nothing private goes in: no real hostnames, IP addresses, home-directory paths or usernames of any machine; no names of private projects, companies or clients; no emails, tokens, keys or `.env` contents. Examples use neutral placeholders such as `server-a` or `https://mcp.example.com`.

## Order Of Work

1. Read the relevant specs and docs.
2. Specify the requirement and its scenarios.
3. Write a failing test for the scenario and watch it fail for the expected reason.
4. Implement the smallest change that makes it pass, then clean up.
5. Update docs when the engineering picture changes.
6. Run `make check` before claiming success or pushing; `make fmt` applies the formatters. When the release config or the build changes, also run `make release-check`. See [Checks and tooling](docs/development/checks.md).

## Quality Bar

- Fix root causes. Do not ship code you cannot explain. State uncertainty and risks explicitly.
- This is a security boundary: tokens, secrets and tool arguments never reach logs or error messages unredacted.
- No abstraction until two real call sites need it. Do not mix unrelated cleanup into a change.
- Fix lint findings instead of silencing them. A `//nolint:<linter>` comment gives its reason on the same line.

## Review And Merge

- Branch from `main`, one topic per branch, conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`).
- Every change goes branch → pull request → green CI → independent review → squash merge.
- The review comes from someone with no stake in the change (a fresh session or subagent) reading the diff with the touched specs and docs. At most three rounds. Each finding is fixed, deferred to an issue, or dropped as taste; the PR description lists deferred and dropped findings with a one-line reason.
- Releases are `v*` tags on `main`, created by the maintainer only; see [Releasing](docs/development/releasing.md).
- Do not add AI attribution lines or trailers to commits or PRs.

## Instruction Files

`AGENTS.md` is the only agent instruction file. Do not add `CLAUDE.md` or tool-specific copies (Copilot, Cursor, Windsurf, Cline and the like); CI rejects them.

## Map

| Path | Contents |
| --- | --- |
| `cmd/mcp-gate/` | The `mcp-gate` binary: subcommands, flags, environment |
| `internal/audit/` | The audit record of a request, its kinds and outcomes, the sink interface and the `call` line writer |
| `internal/compare/` | Catalog reading, normalisation, diff and snapshots for `mcp-gate compare` |
| `internal/config/` | Config file: strict YAML, `${VAR}` expansion, defaults, validation |
| `internal/config/importer/` | Conversion of an mcp-proxy `config.json` for `mcp-gate import` |
| `internal/downstream/` | Supervisor of one downstream server: stdio line connection, size-limited HTTP client, probes, restarts, version pin, notifications |
| `internal/escrow/` | Secret escrow: key hash sources, in-memory store, replacer that keeps findings, the restore procedure, kept files, the frozen `/_escrow/` HTTP API, its failed-auth limit, the unix socket with peer credentials |
| `internal/filescan/` | Scanning of the files download tools write: paths, safe opening under roots, withholding, failing closed |
| `internal/gate/` | `mcp-gate serve` assembled: per-server runtimes, mirrors and routes in a snapshot per config, the aggregate route, its token check and its views per access and token policy, readiness, `/_status`, learned pins file, reloads and the classification of config fields, shutdown |
| `internal/oauth/` | OAuth client of HTTP servers: discovery, registration and login for `mcp-gate auth`, the grant store, the token source that refreshes |
| `internal/policy/` | Server filters and token policy filters, their decisions, the one algorithm for which resource URIs may be read, URI normalization |
| `internal/proxy/` | Source of one server (catalog sync, counters, progress, notification queue) and its mirror under one config with its per-token servers, the request pipeline of calls (checks, forwarding, result redaction), the errors of hidden entries, audit records; the aggregate catalog of several mirrors and its per-access views |
| `internal/procutil/` | Child processes: clean environment, process groups, stderr line log, OOM score, non-dumpable gate, subreaper |
| `internal/redact/` | Redaction engine: rules with priorities, findings, replacers (no MCP or HTTP imports) |
| `internal/redact/mcpredact/` | Redaction of MCP SDK results and errors, failing closed |
| `internal/smoke/` | The binary smoke test: a built `mcp-gate` run as a process against fake servers |
| `internal/systemd/` | Socket activation and readiness notification, without a systemd library |
| `internal/testkit/` | Fake MCP servers for tests: catalog hub, scriptable stdio and HTTP fakes, a fake behind OAuth; the escrow contract check |
| `internal/upstream/` | HTTP listener side: limits, the drain at shutdown, named tokens, Host check, request log, health and status handlers |
| `internal/version/` | Build version and commit |
| `packaging/systemd/` | The system and user systemd services and sockets shipped in the release archives |
| `openspec/specs/` | Behavior specifications, one directory per capability |
| [`docs/`](docs/README.md) | Engineering documentation |
| `scripts/` | Repository checks run by `make repo` |
| `.githooks/` | Versioned git hooks, enabled by `make hooks` |
| `tools/`, `tools/lint/` | Pinned development tools, run with `go tool` |
| `.github/workflows/` | CI (`make check`, tests on macOS, the release config) and the tag-driven release |
| `.github/dependabot.yml` | Weekly grouped dependency updates: the Go module, the pinned tools, the actions |
| `.github/pull_request_template.md` | The pull request description: what, why, specs and docs, verification, review |
| `.github/ISSUE_TEMPLATE/` | Bug and feature issue forms; blank issues are off and vulnerabilities go to private reports |
| `.github/CONTRIBUTING.md` | The short path for contributors, pointing here |
| `SECURITY.md` | How to report a vulnerability, supported versions, scope |
| `.gitguardian.yaml` | Paths the GitGuardian secret scan skips: tests and `testdata/` |
| `.goreleaser.yaml` | Release builds, the smoke test of each built binary, the archives |
