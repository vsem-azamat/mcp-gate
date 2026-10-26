// Package smoke holds the binary smoke test: it runs a built mcp-gate binary as a separate
// process against fake downstream servers, the way systemd runs it, and checks what an operator
// relies on. It has no code of its own; see smoke_test.go and docs/development/testing.md.
package smoke
