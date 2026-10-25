# mcp-gate

mcp-gate is going to be a gateway for [Model Context Protocol](https://modelcontextprotocol.io) servers: one endpoint per downstream MCP server, a token per client, tool allowlists and secret redaction. It is planned to build on the official [Go SDK](https://github.com/modelcontextprotocol/go-sdk).

Status: early development. The gateway itself does not exist yet; `mcp-gate compare`, which diffs the catalogs two MCP endpoints serve, works: see [docs/commands/compare.md](docs/commands/compare.md).

Development: see [docs/development/README.md](docs/development/README.md). License: [Apache-2.0](LICENSE).
