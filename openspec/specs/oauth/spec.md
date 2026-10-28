# oauth Specification

## Purpose

An HTTP downstream server with an `oauth` block is reached with an OAuth access token. mcp-gate is the OAuth client: `mcp-gate auth login` obtains a grant for one server through the authorization code flow, the user signing in from any browser while the gate host needs none, and keeps it on disk; the supervisor sends the grant's access token and refreshes it. The gate never starts a login on its own: a server without a usable grant waits, reported as needing a login: nothing is sent to it, its calls fail, and its route answers 503 until it has connected once. `mcp-gate auth status` shows the grants and `mcp-gate auth logout` deletes one.

## Requirements

### Requirement: Discovery

`auth login` SHALL find the server's authorization server as the MCP authorization specification (2025-11-25) has it: it SHALL send the server an unauthenticated request and read the `resource_metadata` and `scope` of a `Bearer` challenge in a 401 answer; then read the protected resource metadata (RFC 9728) at the challenge's URL, at `/.well-known/oauth-protected-resource` followed by the endpoint's path, or at the root for the origin, the first that names the resource it was fetched for (for an endpoint whose path ends in a slash, the first two also count when they name the endpoint without that slash, a deliberate relaxation of RFC 9728's identical-resource rule limited to the same origin and path); then read the metadata of its first authorization server (RFC 8414, or OpenID Connect discovery), whose `issuer` SHALL equal the authorization server. When `authServerMetadataURL` is set, the metadata SHALL be read there instead, the issuer SHALL be derived from its well-known form, and that issuer SHALL be one of the authorization servers the resource metadata lists. Without protected resource metadata, the server's origin SHALL be taken as the authorization server and the server's URL as the resource. The metadata SHALL offer the `code` response type (when it lists response types), PKCE with `S256`, and authorization, token and registration endpoints that are https or on a loopback address; a login SHALL fail otherwise. The server's URL SHALL be https or on a loopback address. Metadata documents SHALL be read through the SDK, which bounds them to 1 MiB, follows redirects only to https and, unless an HTTP proxy is configured, refuses connections to private and reserved addresses. Requests to the server and to the token and registration endpoints SHALL refuse every connection to a loopback, private, link-local, multicast, unspecified or otherwise reserved address (cloud metadata services among them), checked on each address dialed after the name is resolved, so that a name resolving to such an address at the time of the connection is refused too, unless the server's URL is written with such an address, `localhost` or a name ending in `.localhost` (a local or LAN server, whose authorization server may be local too); a name that only resolves to such an address does not count, since the server's operator controls its DNS. Requests to the configured server's own host and port SHALL not be refused for a non-public address, since its MCP traffic goes there anyway, so a server on a LAN or tailnet name answers the first request of a login; the SDK's guard of metadata documents still refuses such addresses, so its login works only when its metadata is public or behind a proxy. Link-local addresses, the other addresses of cloud metadata services (`fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`) and IPv6 forms that embed an IPv4 address (IPv4-compatible, IPv4-translated, NAT64, 6to4, Teredo) SHALL be refused always, for a local server and for the server's own host too. Behind an HTTP proxy from the environment, the proxy itself SHALL be allowed; a target named as a cloud metadata service (`metadata`, `metadata.google.internal`, `metadata.goog`, `instance-data`, `instance-data.ec2.internal`) SHALL be refused in every case, and a target written as a refused address, in a numeric form a resolver may read as an address (such as `127.1`, `2130706433` or `0x7f000001`), or, for a server that is not local and a target that is not the server's own host and port, as a local name, a single-label name or a name under `.internal`, `.local`, `.lan`, `.home.arpa`, `.localdomain`, `.intranet` or `.corp` SHALL be refused, while other names are left to the proxy to resolve, unchecked.

#### Scenario: Token endpoint on a private address

- **WHEN** the server is at `https://mcp.example.com/mcp`, which resolves to a public address, and its authorization server's metadata names a token endpoint at `http://169.254.169.254/token`, or at a name that resolves to `127.0.0.1`
- **THEN** the token request is refused without a connection to that address

#### Scenario: Local server

- **WHEN** the server is at `http://127.0.0.1:8080/mcp` and its token endpoint at `http://localhost:9000/token`
- **THEN** the token request is sent, while one to `http://169.254.169.254/token` is refused

#### Scenario: Full discovery

- **WHEN** a server answers 401 with a challenge naming its resource metadata, which names an authorization server with dynamic registration
- **THEN** the login finds the authorization server and its endpoints without any of them configured

#### Scenario: Issuer mismatch

- **WHEN** the authorization server's metadata names another issuer than the one it was fetched for
- **THEN** the login fails before anything is sent to its endpoints

#### Scenario: Metadata URL of another authorization server

- **WHEN** `authServerMetadataURL` names an issuer that the resource metadata does not list
- **THEN** the login fails

### Requirement: Client

With `clientID` set, the login SHALL use that client, with `clientSecret` when set, authenticating to the token endpoint in the form body when the server lists `client_secret_post` and with HTTP Basic otherwise. Without it, the login SHALL register a client dynamically (RFC 7591) with the redirect URL, the `authorization_code` and `refresh_token` grant types, the `code` response type, token endpoint authentication `none` and the client name `<config name> (<server>)`, and use the method and secret the server returns; a kept grant's registered client SHALL be reused when it is for the same issuer and redirect URL. A login SHALL fail when there is no client ID and the authorization server offers no registration.

#### Scenario: Registered once

- **WHEN** a server is logged in to twice without a configured client
- **THEN** one client is registered, and the second login reuses it

#### Scenario: Configured client

- **WHEN** `clientID` and `clientSecret` are set and the authorization server offers no registration
- **THEN** the login uses that client, sending its secret with HTTP Basic

### Requirement: Authorization

The authorization URL SHALL carry `response_type=code`, the client ID, the redirect URL, the scopes, a random state of at least 128 bits, a PKCE challenge with method `S256` and the resource (RFC 8707). The scopes SHALL be `scopes` when set, otherwise those of the challenge or else the resource metadata's, with `offline_access` added when the authorization server lists it. `auth login` SHALL print the URL and read one line: the address the browser was sent to (the redirect URL with its query) or its query alone. It SHALL refuse an address that is not the redirect URL (scheme, host and path), whose state differs from the login's, that carries an error (naming the error code and its description, limited to printable ASCII), or whose `iss` (RFC 9207) is not the issuer, or is missing while the metadata says it is sent. The code SHALL be exchanged with the code verifier, the redirect URL and the resource, and the answer SHALL hold a `Bearer` access token.

#### Scenario: PKCE and resource

- **WHEN** a login runs
- **THEN** the authorization request carries `code_challenge_method=S256`, a state and the resource, and the token request the code verifier and the resource

#### Scenario: Pasted address checked

- **WHEN** the pasted address has another host, another state, another issuer or no issuer while one is advertised
- **THEN** the login fails and no grant is kept

### Requirement: Grant store

Grants SHALL be kept in the `oauth` directory of the state directory (`-state-dir`, by default the first entry of `$STATE_DIRECTORY`), one JSON file `<server>.json` each, with `version` 1, the server's URL at login, the resource, the issuer, the authorization and token endpoints, the client ID, a registered client's secret, whether the client was registered, the token endpoint authentication, the redirect URL, the scopes, the access and refresh tokens, the expiry and the times of login and refresh. The directory SHALL be 0700 and each file 0600. A file SHALL be written to a temporary file in the same directory, synced, renamed over the old one, and the directory synced. A file that is a symbolic link, not a regular file, readable or writable by group or others, over 1 MiB, of another version, or with an unknown key SHALL not be used. Writes and refreshes of one server's grant SHALL be serialised between processes by an exclusive lock on `<server>.lock`.

#### Scenario: Permissions

- **WHEN** a grant is saved
- **THEN** its file is 0600 in a 0700 directory and no temporary file is left

#### Scenario: Readable by others

- **WHEN** a grant file is made 0644
- **THEN** it is not used and the error does not quote it

### Requirement: Tokens on requests

A server with an `oauth` block SHALL send every request with `Authorization: Bearer <access token>` from its grant. A grant SHALL be used only for the server URL it was obtained for, and only for the configured client when `clientID` is set, or a registered client when it is not. An access token SHALL be refreshed when it expires within a minute (within half its lifetime, for a token that lives less than two minutes), and when the server answers 401 to it, the request then being retried once. A refresh SHALL send the refresh token and the resource, SHALL keep the old refresh token when the answer has none, and SHALL be saved. Refreshes of one server SHALL run one at a time, under the lock, which is waited for at most 40 seconds. Stopping the server's supervisor SHALL end a wait for the lock at once, so that another process holding the lock cannot hold the stop, and SHALL make later refreshes fail; a token request already sent SHALL run to its end, within 30 seconds, so that a rotated refresh token is saved. When the grant file changed while the lock was awaited (another process refreshed, logged in or logged out), the file SHALL be taken as it is now, as when it is read anew, and the grant in memory SHALL never be saved over it. A 403, and a 401 whose Bearer challenge names `error="insufficient_scope"`, SHALL fail the request without a refresh and SHALL NOT count as a 401 below.

#### Scenario: Server refusing

- **WHEN** the server answers 403 to every request, and then 401 to every token
- **THEN** the 403 fails the requests without a refresh, and after at most three refreshes the server needs a login

#### Scenario: Insufficient scope

- **WHEN** the server answers 401 with `error="insufficient_scope"` to every request
- **THEN** the requests fail without a refresh and the grant stays usable

#### Scenario: Expiry

- **WHEN** several requests need the token while it expires within a minute
- **THEN** it is refreshed once, the rotated refresh token is saved, and another process using the same state directory takes the saved grant without refreshing

#### Scenario: Logout or login during a refresh

- **WHEN** a refresh waits for the lock while `auth logout` deletes the grant, or while `auth login` saves a grant for a new client
- **THEN** the refresh writes nothing back: the server needs a login, or uses the new grant

#### Scenario: Token rejected before its expiry

- **WHEN** the server answers 401 to an access token that has not expired
- **THEN** the token is refreshed and the request succeeds

### Requirement: Fail closed

A server SHALL need a login when it has no grant file, when its grant file cannot be used, when the grant is for another URL or client, when the access token has expired without a refresh token, when the token endpoint answers a refresh with `invalid_grant`, `invalid_client` or `unauthorized_client`, and when the server answers 401 for the third time in a row, each to the token that the refresh after the previous 401 obtained, before any request with that token succeeded; a successful (2xx) answer to a request with such a token SHALL start the count again, however far apart the requests are. Such a server SHALL send no request to its endpoint, and a rejected grant SHALL not be tried again, until its grant file changes: a new login SHALL be used at the next connect attempt without a restart, and a deleted grant SHALL stop being used at the next request. Without a state directory every OAuth server SHALL need a login. Other refresh failures, such as a timeout, SHALL fail only the request.

#### Scenario: Revoked refresh token

- **WHEN** the authorization server revokes the grant and the server is used
- **THEN** the server needs a login, the reason names `invalid_grant`, no token appears in the reason, the error or the log, and the refresh token is not sent again

#### Scenario: Server that drops its tokens repeatedly

- **WHEN** a server drops every access token five times in a row, as one that restarts does, and accepts each refreshed token
- **THEN** every call succeeds after one refresh and the grant stays usable

#### Scenario: Login while the gate runs

- **WHEN** a server needs a login and `auth login` saves a grant
- **THEN** the server connects without the gate restarting

### Requirement: Secrets

Access tokens, refresh tokens, client secrets, codes and code verifiers SHALL appear in no log line, error, status or command output. Errors from the authorization server SHALL name its HTTP status and error code (when it is lower-case letters and underscores, `unknown` otherwise); its error description SHALL be shown only by `auth login`, cut at 200 bytes of printable ASCII. Requests to the authorization server SHALL time out after 30 seconds, follow no redirects (metadata documents excepted, as above) and read at most 1 MiB of an answer.

#### Scenario: Description echoing a token

- **WHEN** the token endpoint refuses a refresh with a description that contains the refresh token
- **THEN** the gate's log and status name the error code only

### Requirement: auth commands

`mcp-gate auth login [-state-dir DIR] <config.yaml> <server>`, `mcp-gate auth status [-state-dir DIR] <config.yaml>` and `mcp-gate auth logout [-state-dir DIR] <config.yaml> <server>` SHALL load the config as `check` does and exit with status 2 when it is invalid, when no state directory is given, or, for `login` and `logout`, when the server is not an HTTP server with an `oauth` block. `login` SHALL print the authorization URL, read the address, save the grant and print the access token's lifetime and whether there is a refresh token; it SHALL exit with status 2 when the login fails, and give up after 15 minutes or on SIGINT. `status` SHALL print, per server with an `oauth` block, sorted, whether it is logged in or needs a login and why, whether the client was registered or configured, the time of login and the access token's lifetime, using no network, and exit with status 0 only when every enabled one is logged in. `logout` SHALL delete the grant file under the grant's lock and let the lock go, and then, when the grant could be read and its authorization server's metadata (read from `authServerMetadataURL` when set, else from the grant's issuer) names a `revocation_endpoint` that is https or loopback, revoke the refresh token and then the access token there (RFC 7009, with `token_type_hint`, the client authenticated as for the token endpoint). An answer `unsupported_token_type` to the access token, after the refresh token was revoked, SHALL count as revoked, since revoking access tokens is optional. `logout` SHALL exit with status 0, saying whether the grant was revoked, that the authorization server offers no revocation endpoint, or, when there was none, that the server was not logged in. A grant that cannot be revoked (the metadata cannot be read or names another issuer, the endpoint is not https or loopback, or it answers otherwise than 200) SHALL be reported on standard error, with status 0: the file is gone all the same. When the file is removed but its directory cannot be synced, `logout` SHALL still revoke the grant, then report the error and exit with status 2.

#### Scenario: Login, status and logout

- **WHEN** a server is checked, logged in to, checked again and logged out of
- **THEN** status first reports `needs login: not logged in` with exit status 2, login prints no token, status then reports `logged in (registered client, …)` with exit status 0, and logout deletes the file

#### Scenario: Logout with revocation

- **WHEN** the authorization server names a revocation endpoint and the server is logged out of
- **THEN** both tokens are revoked there, logout says so, and the file is deleted

#### Scenario: Revocation fails

- **WHEN** the revocation endpoint answers 503 at logout
- **THEN** logout reports the failure without a token, deletes the file and exits with status 0
