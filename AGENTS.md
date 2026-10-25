# mcp-gate Agent Instructions

This file is the working contract for AI agents and contributors in this repository. It says how to work and where to look; facts about the project live in [`docs/`](docs/README.md) and `openspec/specs/`.

## Sources Of Truth

- `openspec/specs/` defines what mcp-gate does. Read the touched capability before changing behavior.
- `docs/` describes how mcp-gate is built and checked today. Start at [`docs/README.md`](docs/README.md).
- Code is the source of truth for how something is implemented. If code and a spec disagree, stop and reconcile them.

## Current State Only

- Everything in the repository is written in English.
- Specs and docs describe the system as it is now: no history, decision logs, plans, roadmaps or status notes.
- A behavior change edits `openspec/specs/` in the same PR as the tests and code that implement it. A PR that changes only specs may reword them but not change behavior. `openspec/changes/` is never committed.
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
6. Run `make check` before claiming success or pushing; `make fmt` applies the formatters. See [Development](docs/development.md).

## Quality Bar

- Fix root causes. Do not ship code you cannot explain. State uncertainty and risks explicitly.
- This is a security boundary: tokens, secrets and tool arguments never reach logs or error messages unredacted.
- No abstraction until two real call sites need it. Do not mix unrelated cleanup into a change.
- Fix lint findings instead of silencing them. A `//nolint:<linter>` comment gives its reason on the same line.

## Review And Merge

- Branch from `main`, one topic per branch, conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`).
- Every change goes branch → pull request → green CI → independent review → squash merge.
- The review comes from someone with no stake in the change (a fresh session or subagent) reading the diff with the touched specs and docs. At most three rounds. Each finding is fixed, deferred to an issue, or dropped as taste; the PR description lists deferred and dropped findings with a one-line reason.
- Do not add AI attribution lines or trailers to commits or PRs.

## Instruction Files

`AGENTS.md` is the only agent instruction file. Do not add `CLAUDE.md` or tool-specific copies; CI rejects them.

## Map

| Path | Contents |
| --- | --- |
| `cmd/mcp-gate/` | The `mcp-gate` binary |
| `openspec/specs/` | Behavior specifications |
| [`docs/`](docs/README.md) | Engineering documentation |
| `scripts/` | Repository checks run by `make repo` |
| `tools/`, `tools/lint/` | Pinned development tools, run with `go tool` |
| `.github/workflows/ci.yml` | CI: the same checks as `make check` |
