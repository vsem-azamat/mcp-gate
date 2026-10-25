# Architecture

[Docs](../README.md) / **Architecture**

How the parts of mcp-gate are put together. Behaviour is specified in `openspec/specs/`; these pages describe the code that implements it.

| Page | Contents |
| --- | --- |
| [Downstream servers](downstream.md) | Supervisors, stdio children and the HTTP client that connect to downstream servers |
| [Escrow and file scanning](escrow.md) | The secret escrow, its HTTP API and failed-auth limit, and the scanning of downloaded files |
| [Redaction](redaction.md) | The redaction engine, its rules and priorities, and the MCP adapter |
| [Serving](serving.md) | The listener, routes and tokens, the catalog mirror, call forwarding, health and status |
