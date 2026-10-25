package compare

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/version"
)

// Source yields the catalog of a named server.
type Source interface {
	Catalog(ctx context.Context, server string) (Catalog, error)
}

// ServerPlaceholder is replaced by the server name in an endpoint template.
const ServerPlaceholder = "{server}"

// redacted replaces a token wherever it would appear in an error message.
const redacted = "[REDACTED]"

// Endpoint reads catalogs from MCP servers over streamable HTTP, one URL per server.
type Endpoint struct {
	template string
	token    string
}

// IsEndpoint reports whether a source argument names an endpoint rather than a snapshot file.
func IsEndpoint(arg string) bool {
	return strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://")
}

// NewEndpoint returns an endpoint for a URL template containing ServerPlaceholder. A non-empty
// token is sent as a bearer token. The template may carry no credentials of its own: no user
// information and no query string.
func NewEndpoint(template, token string) (*Endpoint, error) {
	if !strings.Contains(template, ServerPlaceholder) {
		return nil, fmt.Errorf("endpoint template has no %s", ServerPlaceholder)
	}
	u, err := url.Parse(strings.ReplaceAll(template, ServerPlaceholder, "server-1"))
	if err != nil {
		return nil, errors.New("endpoint template is not a valid URL")
	}
	// The server name must not choose where the token goes: it may only be in the path.
	u2, err := url.Parse(strings.ReplaceAll(template, ServerPlaceholder, "server-2"))
	if err != nil {
		return nil, errors.New("endpoint template is not a valid URL")
	}
	switch {
	case u.Scheme != u2.Scheme || u.Host != u2.Host || u.User.String() != u2.User.String() ||
		u.RawQuery != u2.RawQuery || u.Fragment != u2.Fragment:
		return nil, fmt.Errorf("endpoint template may have %s only in its path", ServerPlaceholder)
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("endpoint template must be an http or https URL")
	case u.Host == "":
		return nil, errors.New("endpoint template has no host")
	case u.User != nil:
		return nil, errors.New("endpoint template must not contain user information; pass tokens through the environment")
	case u.RawQuery != "" || u.ForceQuery:
		return nil, errors.New("endpoint template must not contain a query string; pass tokens through the environment")
	case u.Fragment != "":
		return nil, errors.New("endpoint template must not contain a fragment")
	}
	return &Endpoint{template: template, token: token}, nil
}

// ValidServerName reports whether a server name can be put into an endpoint URL. A name starting
// with "-" is rejected too, since it is a flag given after the server names.
func ValidServerName(name string) bool {
	return name != "" && !strings.HasPrefix(name, "-") && !strings.Contains(name, "/")
}

// URL is the endpoint URL of a server.
func (e *Endpoint) URL(server string) string {
	return strings.ReplaceAll(e.template, ServerPlaceholder, url.PathEscape(server))
}

// Catalog connects to the server's endpoint and reads every page of its lists. Lists whose
// capability the server does not advertise are empty.
func (e *Endpoint) Catalog(ctx context.Context, server string) (Catalog, error) {
	if !ValidServerName(server) {
		return Catalog{}, fmt.Errorf("invalid server name %q", server)
	}
	cat, err := e.read(ctx, server)
	if err != nil && e.token != "" {
		// Defence in depth: the token is only ever in a request header, but no error may carry it.
		err = errors.New(strings.ReplaceAll(err.Error(), e.token, redacted))
	}
	return cat, err
}

func (e *Endpoint) read(ctx context.Context, server string) (Catalog, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return Catalog{}, errors.New("the default HTTP transport is not an *http.Transport")
	}
	transport := base.Clone()
	defer transport.CloseIdleConnections()
	var rt http.RoundTripper = transport
	if e.token != "" {
		rt = bearer{token: e.token, next: transport}
	}
	httpClient := &http.Client{
		Transport: rt,
		// A redirect could take the bearer token to another host, so none is followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-gate", Version: version.Get().Version}, &mcp.ClientOptions{
		Capabilities:   &mcp.ClientCapabilities{},
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             e.URL(server),
		HTTPClient:           httpClient,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return Catalog{}, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = cs.Close() }()

	caps := cs.InitializeResult().Capabilities
	if caps == nil {
		caps = &mcp.ServerCapabilities{}
	}
	var cat Catalog
	if caps.Tools != nil {
		if cat.Tools, err = collect(cs.Tools(ctx, nil)); err != nil {
			return Catalog{}, fmt.Errorf("list tools: %w", err)
		}
	}
	if caps.Prompts != nil {
		if cat.Prompts, err = collect(cs.Prompts(ctx, nil)); err != nil {
			return Catalog{}, fmt.Errorf("list prompts: %w", err)
		}
	}
	if caps.Resources != nil {
		if cat.Resources, err = collect(cs.Resources(ctx, nil)); err != nil {
			return Catalog{}, fmt.Errorf("list resources: %w", err)
		}
		if cat.ResourceTemplates, err = collect(cs.ResourceTemplates(ctx, nil)); err != nil {
			return Catalog{}, fmt.Errorf("list resource templates: %w", err)
		}
	}
	cat.sort()
	return cat, nil
}

func collect[T any](seq iter.Seq2[*T, error]) ([]*T, error) {
	var out []*T
	for item, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// bearer adds the token to every request it sends.
type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}
