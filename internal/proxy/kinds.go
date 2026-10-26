package proxy

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// auditKey is the attribute of an audit line that names what a request is for, which also
// tells the request's kind.
type auditKey string

// The audit keys.
const (
	keyTool   auditKey = "tool"
	keyPrompt auditKey = "prompt"
	keyURI    auditKey = "uri"
)

// entryKind names a kind of catalog entry in log lines.
type entryKind string

// The kinds of catalog entries.
const (
	entryTool     entryKind = "tool"
	entryPrompt   entryKind = "prompt"
	entryResource entryKind = "resource"
	entryTemplate entryKind = "resource template"
)

// keySep joins a kind and a name in the keys of left-out entries; neither can hold it.
const keySep = "\x00"

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
