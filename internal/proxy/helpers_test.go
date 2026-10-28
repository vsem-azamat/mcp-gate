package proxy

import "github.com/modelcontextprotocol/go-sdk/mcp"

// The server filter and register steps of one kind, as a listing runs them, without the views.

func (m *Mirror) applyTools(list []*mcp.Tool) map[string]*mcp.Tool {
	return m.registerTools(m.filterTools(list, nil))
}

func (m *Mirror) applyResources(list []*mcp.Resource) map[string]*mcp.Resource {
	return m.registerResources(m.filterResources(list))
}

func (m *Mirror) applyTemplates(list []*mcp.ResourceTemplate) map[string]*mcp.ResourceTemplate {
	return m.registerTemplates(m.filterTemplates(list))
}
