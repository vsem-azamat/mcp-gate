# Development

[Docs](../README.md) / **Development**

## Setup

Go (the version in [`go.mod`](../../go.mod)), Git and Bash are all that is needed. After cloning, enable the versioned git hooks once:

```sh
make hooks   # git config core.hooksPath .githooks
```

Then `make check` runs the checks. The hooks and the checks are described in [Checks and tooling](checks.md).

| Page | Contents |
| --- | --- |
| [Checks and tooling](checks.md) | Make targets, git hooks, tool pinning, CI and dependency updates |
| [Testing](testing.md) | The fake MCP servers, the goroutine leak check, fuzzing and benchmarks |
| [Releasing](releasing.md) | How a `v*` tag on `main` becomes a GitHub release |
