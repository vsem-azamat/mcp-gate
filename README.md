<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/wordmark-dark.svg">
    <img alt="mcp-gate" src=".github/assets/wordmark-light.svg" width="360">
  </picture>
  <p>
    <a href="https://github.com/vsem-azamat/mcp-gate/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/vsem-azamat/mcp-gate/ci.yml?branch=main&style=flat&label=CI"></a>
    <a href="https://github.com/vsem-azamat/mcp-gate/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/vsem-azamat/mcp-gate?style=flat&label=Latest%20release&color=0969da"></a>
    <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/vsem-azamat/mcp-gate?style=flat"></a>
    <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg?style=flat"></a>
    <a href="https://github.com/vsem-azamat/mcp-gate"><img alt="Stars" src="https://img.shields.io/github/stars/vsem-azamat/mcp-gate?style=flat&logo=github&label=Stars"></a>
  </p>
  <p><strong>A self-hosted gate between your AI agents and your MCP servers.</strong></p>
</div>

---

mcp-gate sits between your AI agents and your [MCP](https://modelcontextprotocol.io) servers. Each server gets its own URL, each agent gets its own token, and passwords or API keys in a server's answer are hidden before the agent sees them. It is one Go binary, built on the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk).

<br>
<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/request-path-dark.svg">
  <img alt="Your AI agents (Claude Code, Codex, Cursor) each have their own token. mcp-gate checks who is calling and whether the tool is allowed, blocks the call if not, and passes it to the right MCP server. On the way back it hides secrets in answers and in downloaded files and logs who did what. The animation follows one call: read_file returns the line password: hunter2, the agent gets password: [REDACTED #k3j5] instead, the password waits in the secret vault, and the owner reads it back with their own key." src=".github/assets/request-path-light.svg" width="880">
</picture>
</div>
<br>

## Why I wrote it

I run about a dozen MCP servers for my own agents. I wanted secrets hidden from the model, a way to read a hidden value myself, a name on every token so the log shows who called what, OAuth that works with real providers, and new protocol versions soon after they come out. The open-source gateways I tried each had some of this, none had all of it. I patched one of them for a while, but my pull requests there waited a long time for review. So I wrote my own.

## Key features

- **A URL per server**<br>
  Local (stdio) and remote (Streamable HTTP) servers are served at `/<server>/mcp`. The gate starts local servers, checks that they respond and restarts them when they crash. While a server restarts, agents can still list its tools.

- **A token per agent**<br>
  Each token has a name, and the log line for every call says which token made it. A token can work for all servers or for one, and a server can be open without a token.

- **Allow and deny lists**<br>
  Choose which tools, prompts and resources each server shows to agents.

- **Hidden secrets**<br>
  API keys, private keys, `Authorization` headers, `.env` lines and passwords in URLs become `[REDACTED:<kind>]` in answers, error messages and server logs. If the gate cannot check an answer, the agent gets an error instead. Files a tool downloads are checked too.

- **Secret vault**<br>
  Optional. Hidden values stay in memory for a day, and only your own key reads them back. Agent tokens cannot.

- **OAuth for remote servers**<br>
  `mcp-gate auth login` signs in once in any browser. The gate stores the grant and refreshes it.

- **Easy to run and to move to**<br>
  Health endpoints, a `/_status` page, JSON logs that never contain arguments or answers, and systemd units. `import` converts a [TBXark/mcp-proxy](https://github.com/TBXark/mcp-proxy) config, and `compare` shows what differs between two gateways.

## How it compares

| | **mcp-gate** | [mcp-proxy](https://github.com/TBXark/mcp-proxy) | [Docker](https://github.com/docker/mcp-gateway) | [ContextForge](https://github.com/IBM/mcp-context-forge) | [agentgateway](https://github.com/agentgateway/agentgateway) |
| --- | :---: | :---: | :---: | :---: | :---: |
| A URL per server | ✅ | ✅ | ❌ | ➖ | ✅ |
| A named token per agent | ✅ | ❌ | ❌ | ✅ | ✅ |
| Filters for tools, prompts, resources | ✅ | ➖ | ➖ | ✅ | ✅ |
| Hides secrets in answers | ✅ | ❌ | ➖ | ➖ | ➖ |
| Secret vault for the owner | ✅ | ❌ | ❌ | ❌ | ❌ |
| OAuth to remote servers | ✅ | ✅ | ✅ | ✅ | ➖ |
| One binary, no database | ✅ | ✅ | ❌ | ❌ | ✅ |
| All tools behind one URL | [🔜](https://github.com/vsem-azamat/mcp-gate/issues/28) | ❌ | ✅ | ✅ | ✅ |
| Different tools for different agents | [🔜](https://github.com/vsem-azamat/mcp-gate/issues/32) | ❌ | ❌ | ✅ | ✅ |
| Web UI | ❌ | ❌ | ➖ | ✅ | ✅ |
| SSO and roles | ❌ | ❌ | ❌ | ✅ | ✅ |
| Legacy SSE transport | [🔜](https://github.com/vsem-azamat/mcp-gate/issues/37) | ✅ | ❔ | ✅ | ✅ |

<sub>🔜 planned, links to the issue. ➖ partly: tools only; Docker blocks the whole call instead of hiding the secret; ContextForge and agentgateway hide secrets through plugins; agentgateway's OAuth is token exchange. ❔ not documented. Checked against each project's docs in October 2026, corrections welcome.</sub>

mcp-gate suits a handful of MCP servers on one machine. If you need what the lower rows list, look at ContextForge, agentgateway, [MetaMCP](https://github.com/metatool-ai/metamcp) or [MCPJungle](https://github.com/mcpjungle/MCPJungle).

## Getting started

Download an archive for Linux or macOS (amd64 or arm64) from [Releases](https://github.com/vsem-azamat/mcp-gate/releases) and check it against `checksums.txt`. You can also build from source with Go 1.27 or newer:

```sh
go install github.com/vsem-azamat/mcp-gate/cmd/mcp-gate@latest
```

Create `gate.yaml`:

```yaml
version: 1
listen:
  addr: 127.0.0.1:9090
auth:
  tokens:
    laptop: "${GATE_TOKEN_LAPTOP}"   # the name shows up in the audit log
servers:
  files:
    stdio:
      command: npx
      args: [-y, "@modelcontextprotocol/server-filesystem", /srv/shared]
    tools: {deny: [write_file, move_file]}
  docs:
    http:
      url: https://docs.example.com/mcp
      oauth: {}                      # run `mcp-gate auth login gate.yaml docs` once
```

Check the config, then run the gate:

```sh
export GATE_TOKEN_LAPTOP=$(openssl rand -hex 32)
mcp-gate check -connect gate.yaml
mcp-gate serve gate.yaml
```

Point a client at a server's endpoint:

```json
{
  "mcpServers": {
    "files": {
      "type": "http",
      "url": "http://127.0.0.1:9090/files/mcp",
      "headers": {"Authorization": "Bearer <GATE_TOKEN_LAPTOP>"}
    }
  }
}
```

The [configuration reference](docs/configuration/README.md) lists every key. To run the gate as a service, see [systemd](docs/operations/systemd.md).

## Commands

| Command | What it does |
| --- | --- |
| [`serve`](docs/commands/serve.md) | Run the gateway |
| [`check`](docs/commands/check.md) | Validate a config; with `-connect`, also start every server once and report what it serves |
| [`auth`](docs/commands/auth.md) | `login`, `status` and `logout` for OAuth servers |
| [`compare`](docs/commands/compare.md) | Diff the tools, prompts and resources of two endpoints or snapshots |
| [`import`](docs/commands/import.md) | Convert an mcp-proxy `config.json` |

## Documentation

| | |
| --- | --- |
| [Configuration](docs/configuration/README.md) | Every key, its default and its meaning |
| [Commands](docs/commands/README.md) | How to use each subcommand |
| [Operations](docs/operations/README.md) | systemd units, running behind a reverse proxy, switching from mcp-proxy |
| [Architecture](docs/architecture/README.md) | How serving, downstreams, redaction, escrow and OAuth are built |
| [Specifications](openspec/specs/) | The exact behaviour, as requirements and scenarios |
| [Development](docs/development/README.md) | Setup, checks, tests and releases |

## Status

Version 0.1. I use it every day with about a dozen servers. The config has a version number (`version: 1`), and an unknown key is an error. The gate does not reload its config yet, so restart it after a change. Missing something? [Open an issue](https://github.com/vsem-azamat/mcp-gate/issues).

## Contributing

Issues, fixes and features are welcome. I answer issues and review pull requests as soon as I can, usually within a day or two. Start with [CONTRIBUTING](.github/CONTRIBUTING.md); [AGENTS.md](AGENTS.md) has the working rules, and security issues go through [private reporting](https://github.com/vsem-azamat/mcp-gate/security/advisories/new).

## Contributors

<a href="https://github.com/vsem-azamat/mcp-gate/graphs/contributors">
  <img alt="Contributors" src="https://contrib.rocks/image?repo=vsem-azamat/mcp-gate">
</a>

---

<div align="center">
  <sub>mcp-gate is released under the <a href="LICENSE">Apache 2.0 license</a>.</sub>
</div>
