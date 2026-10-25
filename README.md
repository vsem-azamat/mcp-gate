# mcp-gate

mcp-gate is a gateway for [Model Context Protocol](https://modelcontextprotocol.io) servers. It is meant to expose one endpoint per downstream MCP server, authenticate each client with its own token, limit clients to an allowlist of tools and redact secrets from what passes through. It is built on the official [Go SDK](https://github.com/modelcontextprotocol/go-sdk).

Status: early development. Nothing is usable yet.

Development: see [docs/development.md](docs/development.md). License: [Apache-2.0](LICENSE).
