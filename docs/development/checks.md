# Checks And Tooling

[Docs](../../README.md) / [Development](README.md) / **Checks and tooling**

## Requirements

Go (the version in [`go.mod`](../../go.mod)), Git and Bash. Every other tool is pinned and runs through `go tool`; nothing else needs a global install.

## Checks

`make` is the single entry point, and CI runs the same targets. `make help` lists them.

| Target | What it does |
| --- | --- |
| `make check` | All of the checks below, as CI runs them |
| `make repo` | Repository policy (`scripts/repo-policy-check.sh`), Markdown links and the docs index (`scripts/docs-check.sh`), `.editorconfig` rules (editorconfig-checker; Go files are left to gofumpt), workflow lint (actionlint) |
| `make tidy-check` | `go.mod` and `go.sum` are tidy in every module; `make tidy` fixes them |
| `make lint` | golangci-lint v2 with the config in [`.golangci.yml`](../../.golangci.yml), including the gofumpt and goimports formatting check |
| `make fmt` | Applies gofumpt and goimports |
| `make test` | `go test -race -shuffle=on ./...` |
| `make vuln` | govulncheck over the code and its dependencies |

The repository policy rejects `CLAUDE.md` and similar tool-specific instruction files, anything under `openspec/changes/`, scratch and temporary files, workflow actions not pinned to a full commit SHA, and workflows that run different GoReleaser versions.

## Tool Pinning

Development tools are `tool` directives in their own modules, so their dependencies never enter the product's `go.mod`:

- [`tools/go.mod`](../../tools/go.mod): govulncheck, editorconfig-checker, actionlint;
- [`tools/lint/go.mod`](../../tools/lint/go.mod): golangci-lint, in a module of its own because its dependency tree is large.

They run as `go tool -modfile=tools/go.mod <tool>` (the Makefile wraps this). To upgrade a tool, run `go get -tool <package>@<version>` in its module directory, then `make tidy check`.

## CI

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs on every pull request and on pushes to `main`, with read-only permissions. The jobs are Repository checks, Lint, Test, Vulnerabilities and Release config (see [Releasing](releasing.md)); the `CI` job succeeds only when all of them succeed and is the one status check to require. Actions are pinned to full commit SHAs with the version in a comment.

## Dependency Updates

Dependabot ([`.github/dependabot.yml`](../../.github/dependabot.yml)) opens one grouped pull request a week for the Go modules (the product and both tool modules) and one for GitHub Actions.
