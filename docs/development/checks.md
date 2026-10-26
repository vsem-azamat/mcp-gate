# Checks And Tooling

[Docs](../README.md) / [Development](README.md) / **Checks and tooling**

## Make Targets

`make` is the single entry point; `make help` lists the targets. Nothing needs a global install besides Go, Git and Bash.

| Target | What it does |
| --- | --- |
| `make check` | `repo`, `tidy-check`, `lint`, `test` and `vuln`: every CI job but Release config, on the machine's own platform (CI also tests on macOS) |
| `make repo` | Repository policy (`scripts/repo-policy-check.sh`), Markdown links and the docs tree (`scripts/docs-check.sh`), `.editorconfig` rules (editorconfig-checker; Go files are left to gofumpt), workflow lint (actionlint) |
| `make tidy-check` | `go.mod` and `go.sum` are tidy in every module; `make tidy` fixes them |
| `make lint` | golangci-lint v2 with the config in [`.golangci.yml`](../../.golangci.yml), including the gofumpt and goimports formatting check |
| `make fmt` | Applies gofumpt and goimports |
| `make test` | `go test -race -shuffle=on ./...` |
| `make fuzz` | Runs every fuzz target for `FUZZTIME` (default `60s`); not part of `make check` (see [Testing](testing.md)) |
| `make bench` | Runs the benchmarks with allocation counts; not part of `make check` |
| `make vuln` | govulncheck over the code and its dependencies; needs network |
| `make release-check` | `goreleaser check` and a snapshot build into `dist/`, as CI's Release config job does. Not part of `make check`: the first run builds GoReleaser and takes minutes |
| `make hooks` | Enables the git hooks below |

Besides the standard and enabled linters, `.golangci.yml` enforces these project rules:

- `depguard`: `github.com/mark3labs/mcp-go` is not imported; the official `github.com/modelcontextprotocol/go-sdk` is the only MCP library;
- `depguard`: `internal/redact` imports neither `net/http` nor the MCP SDK (its subpackage `mcpredact` is the MCP adapter);
- `forbidigo`: `fmt.Print*` and reading the environment (`os.Getenv`, `os.LookupEnv`, `os.Environ`) only in `cmd/`, which passes values in (the config loader takes a lookup function, supervisors the parent environment); the standard `log` package nowhere (use `log/slog`). The test fakes in `internal/testkit` and the `internal/procutil` test helpers may call `os.Environ`, to report what a child inherited.

The repository policy rejects:

- agent instruction files other than `AGENTS.md`, in any letter case: `CLAUDE.md`, `AGENT.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/`, `.cursorrules`, `.windsurfrules`, `.clinerules*`;
- anything under `openspec/changes/`, scratch, temporary and `.env` files;
- workflow actions not pinned to a full commit SHA;
- GoReleaser versions that differ between the workflows and the Makefile;
- git hooks in `.githooks/` without the executable bit.

The docs check follows inline and reference-style relative links in every tracked Markdown file. In `docs/` it also requires that each directory has a `README.md` index linking every page and subdirectory in it, and that each page but `docs/README.md` has a breadcrumb line `[Docs](…)` pointing to `docs/README.md`.

## Git Hooks

`make hooks` sets `core.hooksPath` to the versioned `.githooks/`; it works the same in a worktree. The hooks build their tools through `go tool` on first use.

- **pre-commit** (seconds) checks the staged Go files for gofumpt and goimports formatting, using the staged content and without rewriting anything; `make fmt` fixes them. It also checks the staged files against `.editorconfig` and runs the repository policy.
- **pre-push** runs `make lint test tidy-check repo`. It skips a push that only deletes remote branches. It checks the working tree, not the commits being pushed, so uncommitted changes count and a commit pushed from another branch is not checked; CI checks the pushed commits. `vuln` and `release-check` are left to CI, since they need network or take long.

Do not bypass them with `--no-verify`.

## Tool Pinning

Development tools are `tool` directives in their own modules, so their dependencies never enter the product's `go.mod`:

- [`tools/go.mod`](../../tools/go.mod): govulncheck, editorconfig-checker, actionlint;
- [`tools/lint/go.mod`](../../tools/lint/go.mod): golangci-lint, in a module of its own because its dependency tree is large.

They run as `go tool -modfile=tools/go.mod <tool>` (the Makefile wraps this). To upgrade a tool, run `go get -tool <package>@<version>` in its module directory, then `make tidy check`.

GoReleaser is the exception: CI runs it through `goreleaser/goreleaser-action` and `make release-check` through `go run` at `GORELEASER_VERSION` in the Makefile. To upgrade it, change the version in `ci.yml`, `release.yml` and the Makefile together; `make repo` fails while they differ.

## CI

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs on every pull request and on pushes to `main`, with read-only permissions. A new push to a pull request cancels its running checks; runs on `main` are never cancelled. The jobs are Repository checks (`make repo tidy-check`), Lint, Test, Test (macOS), Vulnerabilities and Release config (see [Releasing](releasing.md)). Test (macOS) runs `make test` on an arm64 macOS runner, so the code and tests behind `darwin` and `!linux` build tags build and run; the other jobs do not depend on the platform and run on Linux only. The `CI` job succeeds only when all of them succeed and is the one status check to require. Pull requests are also scanned for secrets by the GitGuardian app, outside CI; [`.gitguardian.yaml`](../../.gitguardian.yaml) excludes test files and `testdata/`, which hold made-up credentials. Actions are pinned to full commit SHAs with the version in a comment.

## Dependency Updates

Dependabot ([`.github/dependabot.yml`](../../.github/dependabot.yml)) opens grouped pull requests every week:

- the product's Go module;
- the tool modules, limited to the tools themselves: their other requirements are indirect and stay at what each tool was released with, since bumping them on their own breaks the build;
- GitHub Actions, which covers the action SHAs.

Dependabot does not see the `version:` that the workflows pass to GoReleaser, so GoReleaser is upgraded by hand as described in Tool Pinning.
