# mcp-gate

mcp-gate is going to be a gateway for [Model Context Protocol](https://modelcontextprotocol.io) servers: one endpoint per downstream MCP server, a token per client, tool allowlists and secret redaction. It is planned to build on the official [Go SDK](https://github.com/modelcontextprotocol/go-sdk).

Status: early development. The gateway itself does not exist yet. What works: `mcp-gate compare`, which diffs the catalogs two MCP endpoints serve; `mcp-gate check`, which validates a config; and `mcp-gate import`, which converts an mcp-proxy config. See [docs/commands/](docs/commands/README.md).

Development: see [docs/development/README.md](docs/development/README.md). License: [Apache-2.0](LICENSE).
