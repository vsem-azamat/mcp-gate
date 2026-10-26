# Contributing

1. Read [`AGENTS.md`](../AGENTS.md): it is the working contract for everyone, people and agents alike, and links to the engineering docs.
2. After cloning, run `make hooks` once to enable the git hooks.
3. Run `make check` before pushing; `make fmt` applies the formatters. When the release config or the build changes, also run `make release-check`.
4. Open a pull request from a branch with a conventional commit title (`feat:`, `fix:`, `docs:`, …) and fill in the template. It is squash-merged after CI is green and a review.

Report vulnerabilities privately, as [`SECURITY.md`](../SECURITY.md) describes, not in an issue.
