# mcp-gate

mcp-gate is a gateway for [Model Context Protocol](https://modelcontextprotocol.io) servers: one endpoint per downstream MCP server, named tokens per client, tool, prompt and resource filters, and secret redaction in results. It is built on the official [Go SDK](https://github.com/modelcontextprotocol/go-sdk).

Status: early development. `mcp-gate serve` runs the gateway; `mcp-gate compare` diffs the catalogs two MCP endpoints serve; `mcp-gate check` validates a config and can connect to its servers; and `mcp-gate import` converts an mcp-proxy config. See [docs/commands/](docs/commands/README.md).

Development: see [docs/development/README.md](docs/development/README.md). License: [Apache-2.0](LICENSE).
