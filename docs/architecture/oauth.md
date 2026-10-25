# OAuth

[Docs](../README.md) / [Architecture](README.md) / **OAuth**

How mcp-gate is the OAuth client of the HTTP servers with an `oauth` block. The behaviour is specified in [`openspec/specs/oauth/spec.md`](../../openspec/specs/oauth/spec.md); the commands are in [auth](../commands/auth.md).

## Packages

| Package | Contents |
| --- | --- |
| [`internal/oauth`](../../internal/oauth/doc.go) | `BeginLogin` and `Pending.Complete` (discovery, registration, the authorization code flow), `Store` (grant files and their lock), `Source` (the token source), the token endpoint client |
| [`internal/downstream`](../../internal/downstream/supervisor.go) | The `Authorizer` a supervisor of an OAuth server is given, and the `needs-login` state |
| [`cmd/mcp-gate`](../../cmd/mcp-gate/auth.go) | `mcp-gate auth login`, `status` and `logout` |

## Libraries

The SDK provides the parts that are about MCP: `oauthex.GetProtectedResourceMetadata` and `oauthex.GetAuthServerMeta` (or `auth.GetAuthServerMetadata`, which tries the well-known locations of an issuer) read and check the metadata documents, `oauthex.ParseWWWAuthenticate` reads the 401 challenge, and the streamable client transport takes an `auth.OAuthHandler`. `golang.org/x/oauth2` builds the authorization URL with the PKCE challenge and generates the verifier, and its `TokenSource` is the type the transport asks for.

The SDK's own `auth.AuthorizationCodeHandler` is not used: it runs the whole flow inside the transport when a request gets 401, which a headless gate must never do, has no place to keep the registered client and the refresh token across processes, and cannot read metadata from a configured URL. Token requests (the code exchange and refreshes) are the package's own `requestToken`, because a refresh through `x/oauth2` cannot carry the `resource` parameter, and because its errors quote the response body. Registration is its own for the same reason.

## Login

`BeginLogin` sends the server an unauthenticated `ping` and parses the challenge of a 401 answer. It reads the protected resource metadata at the challenge's URL or at the well-known locations, then the authorization server's metadata, at `authServerMetadataURL` when set; `issuerOf` derives the issuer that document must name from its well-known form. The metadata documents are fetched through the SDK with a client whose transport sets no `DialContext`, so that the SDK clones it with its dial guard against private and reserved addresses (which it drops when a proxy is configured); keep-alives are off, since that clone cannot be closed. Token and registration requests have no such guard. The client is the configured one, the previous grant's registered one when it is for the same issuer and redirect URL, or a new registration. The authorization URL carries a `rand.Text` state, the S256 challenge and the resource.

`Pending.Complete` parses the pasted address, checks the redirect URL, the error, the state (in constant time) and the issuer (RFC 9207), and exchanges the code. `auth login` saves the grant under the store's lock.

## Store

A `Store` is `<state dir>/oauth`. `Save` writes a temporary file (0600) in that directory, syncs, renames and syncs the directory; the directory is created, or reset, to 0700. `load` opens with `O_NOFOLLOW`, checks the mode on the open file, reads at most 1 MiB and decodes strictly. `Lock` takes `flock` on `<server>.lock`. Each load remembers a stamp of the file (identity, size, modification time), which tells a `Source` when another process has written it.

## Source

A `Source` is the transport's `OAuthHandler` and its own `oauth2.TokenSource`. Every `Token` call compares the file's stamp with the one it read, so that a new login or a logout is noticed at the next request, and refreshes the access token when it expires within a minute, or half its lifetime for a short-lived one. `Authorize`, which the transport calls on 401 and 403, refreshes on a 401 to the current token and returns nil, so the transport retries once. The third 401 in a row to a token that the previous such refresh obtained, each within 10 minutes of the one before, or a refresh refused with `invalid_grant`, `invalid_client` or `unauthorized_client`, marks the grant dead until the file changes. A refresh runs under the store's lock (polled with `LOCK_NB` for at most 40 seconds); when the file changed while it waited, the file is read anew and wins, and the refresh goes on only when the grant it finds still needs one, so that a logout, a new login or another process's refresh is never overwritten. Refreshes run on the `Source`'s mutex, so one server refreshes once at a time; a refresh started by a 401 runs on a context that the request's end does not cancel, so that a rotated refresh token is not lost.

Errors carry the token endpoint's status and error code (anything but lower-case letters and underscores becomes `unknown`); the description, which a server could fill with anything, is kept only for `auth login`. Transport errors are stripped of their URL.
