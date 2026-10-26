package proxy

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
)

// kindSet is a set of catalog kinds, such as the kinds a listing holds or a mirror shows.
type kindSet uint8

// allKinds holds every kind.
const allKinds = kindSet(audit.Tool | audit.Prompt | audit.Resource)

// has reports whether the set holds k.
func (s kindSet) has(k audit.Kind) bool { return s&kindSet(k) != 0 }

// entryKind names a kind of catalog entry in log lines.
type entryKind string

// The kinds of catalog entries.
const (
	entryTool     entryKind = "tool"
	entryPrompt   entryKind = "prompt"
	entryResource entryKind = "resource"
	entryTemplate entryKind = "resource template"
)

// named is a tool or prompt of the aggregate catalog, by kind and name, as a map key.
type named struct {
	kind audit.Kind
	name string
}

// listedKey is a resource or resource template, by kind and key, as a map key.
type listedKey struct {
	kind entryKind
	key  string
}

// The errors of a request for an entry the caller cannot see, the same as the SDK's for an entry
// the server does not have, so that a hidden entry cannot be told from a missing one. Every
// refusal of a name the caller may not see goes through these.

// errUnknownTool is the SDK's error for a call of a tool the server does not have.
func errUnknownTool(name string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", name)}
}

// errUnknownPrompt is the SDK's error for a get of a prompt the server does not have.
func errUnknownPrompt(name string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown prompt %q", name)}
}

// errUnknownResource is the SDK's error for a read of a resource the server does not serve.
func errUnknownResource(uri string) error { return mcp.ResourceNotFoundError(uri) }

// errUnknown is the error of a request for a tool, prompt or resource the server does not have,
// named as the caller named it.
func errUnknown(kind audit.Kind, shown string) error {
	switch kind {
	case audit.Prompt:
		return errUnknownPrompt(shown)
	case audit.Resource:
		return errUnknownResource(shown)
	case audit.Tool:
	}
	return errUnknownTool(shown) // a tool's, or what a request of no known kind gets
}
