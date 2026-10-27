// Package oauth is the OAuth client of HTTP downstream servers.
//
// mcp-gate auth login obtains a grant for a server with BeginLogin and Pending.Complete: it
// discovers the authorization server (protected resource metadata, then authorization server
// metadata), registers a client dynamically unless one is configured, and runs the
// authorization code flow with PKCE (S256), the user opening the URL in any browser and pasting
// back the address it was redirected to. The grant is kept in a Store, one file per server.
// mcp-gate auth logout revokes it with Revoke (RFC 7009) when the authorization server offers
// a revocation endpoint.
//
// A Source hands the grant's access token to the SDK's streamable client and refreshes it. It
// never starts a login: a server without a usable grant needs one, which the supervisor reports.
// Tokens never appear in errors or logs.
package oauth
