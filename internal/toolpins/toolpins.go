// Package toolpins pins the definitions of the tools a server lists, so that a server that
// changes a tool's description or schema after it was looked at is noticed. The behaviour is
// specified in openspec/specs/tool-pins/spec.md.
//
// A server's pins are a File: by tool name, the accepted definition and the pending one, a
// definition the server listed that differs from the accepted one. A Store keeps the files in the
// state directory, or in memory without one, and is shared by the gate and the toolpins command,
// which take the server's lock file for every read-modify-write.
package toolpins

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// FileVersion is the version of the pins file this build reads and writes.
const FileVersion = 1

// File is the pins of one server.
type File struct {
	Version int               `json:"version"`
	Server  string            `json:"server"`
	Tools   map[string]*Entry `json:"tools"`
}

// Entry is the pins of one tool: what was accepted, and what the server lists instead, if it
// lists something else. A tool first listed after the server was pinned has only Pending.
type Entry struct {
	Accepted *Pin `json:"accepted,omitempty"`
	Pending  *Pin `json:"pending,omitempty"`
}

// Pin is one definition of a tool, its hash, and when it was recorded.
type Pin struct {
	Hash       string          `json:"hash"`
	Definition json.RawMessage `json:"definition"`
	At         time.Time       `json:"at"`
}

// The kinds of change of a tool.
const (
	// Changed is a tool whose listed definition differs from its accepted one.
	Changed = "changed"
	// Added is a tool without an accepted definition on a server that has pins.
	Added = "added"
)

// Change returns the kind of change a pending entry is: Changed or Added; "" without one.
func (e *Entry) Change() string {
	switch {
	case e == nil || e.Pending == nil:
		return ""
	case e.Accepted == nil:
		return Added
	default:
		return Changed
	}
}

// Pending returns the names of the tools with a pending definition.
func (f *File) Pending() []string {
	var out []string
	for name, e := range f.Tools {
		if e.Pending != nil {
			out = append(out, name)
		}
	}
	return out
}

// Accepted counts the tools with an accepted definition.
func (f *File) Accepted() int {
	n := 0
	for _, e := range f.Tools {
		if e.Accepted != nil {
			n++
		}
	}
	return n
}

// definition is what of a tool is pinned: everything the gate serves of it, what a model or a
// client reads. _meta is pinned too: its keys are the server's own, and some steer clients, such
// as the UI resource a tool's result is shown in.
type definition struct {
	Meta         mcp.Meta             `json:"_meta,omitempty"`
	Name         string               `json:"name"`
	Title        string               `json:"title,omitempty"`
	Description  string               `json:"description,omitempty"`
	InputSchema  any                  `json:"inputSchema,omitempty"`
	OutputSchema any                  `json:"outputSchema,omitempty"`
	Annotations  *mcp.ToolAnnotations `json:"annotations,omitempty"`
	Icons        []mcp.Icon           `json:"icons,omitempty"`
}

// Define returns the canonical definition of a tool and its hash, "sha256:<hex>". The definition
// is JSON with object keys sorted and no insignificant space, so that neither changes the hash.
func Define(t *mcp.Tool) (json.RawMessage, string, error) {
	raw, err := json.Marshal(definition{
		Meta: t.Meta, Name: t.Name, Title: t.Title, Description: t.Description,
		InputSchema: t.InputSchema, OutputSchema: t.OutputSchema, Annotations: t.Annotations, Icons: t.Icons,
	})
	if err != nil {
		return nil, "", err
	}
	canon, err := canonical(raw)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canon)
	return canon, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// canonical re-encodes JSON with object keys sorted, numbers as written and no HTML escaping.
func canonical(raw []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
