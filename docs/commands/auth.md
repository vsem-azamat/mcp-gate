# auth

[Docs](../README.md) / [Commands](README.md) / **auth**

`mcp-gate auth` manages the OAuth grants of the HTTP servers that have an `oauth` block (see [Configuration](../configuration/README.md)). The behaviour is specified in [`openspec/specs/oauth/spec.md`](../../openspec/specs/oauth/spec.md); how it is built is in [OAuth](../architecture/oauth.md).

The grants live in the `oauth` directory of the gate's state directory. Run the commands as the gate's user, with its environment (the config must load), and point `-state-dir` at the directory `serve` uses; it defaults to `$STATE_DIRECTORY`.

## login

`mcp-gate auth login <config.yaml> <server>` discovers the server's authorization server, registers a client unless `oauth.clientID` is set, and prints a URL. Open it in a browser on any machine and sign in. The browser is then sent to the redirect URL, by default `http://localhost:8090/oauth/callback`, a page that does not load: copy the whole address from the address bar and paste it.

```console
$ mcp-gate auth login -state-dir /var/lib/mcp-gate gate.yaml mail
Registered an OAuth client with the authorization server.
Open this URL in a browser and sign in:

  https://auth.example.com/authorize?client_id=…&code_challenge=…&code_challenge_method=S256&…

The browser is then sent to http://localhost:8090/oauth/callback?code=..., a page that does not load.
Copy that whole address from the address bar and paste it here.

Address: http://localhost:8090/oauth/callback?code=…&state=…

Logged in to mail: access token valid for 1h0m0s, with a refresh token.
```

The address is checked against the redirect URL, the login's state and the issuer before the code is exchanged. A running gate uses the new grant at the server's next connect attempt, within `restart.maxBackoff`; no restart is needed. Logging in again replaces the grant and reuses the registered client.

## status

`mcp-gate auth status <config.yaml>` reads the grants without the network:

```console
$ mcp-gate auth status -state-dir /var/lib/mcp-gate gate.yaml
docs: needs login: not logged in
mail: logged in (registered client, since 2026-01-01T09:00:00Z): access token valid for 42m0s, with a refresh token
```

Exit status: 0 when every enabled OAuth server is logged in, 2 otherwise.

## logout

`mcp-gate auth logout <config.yaml> <server>` deletes the server's grant and then revokes it at its authorization server; a running gate stops using it at its next request and the server needs a login. The revocation (RFC 7009) needs a `revocation_endpoint` in the authorization server's metadata, which logout reads again (from `authServerMetadataURL` when it is set); it revokes the refresh token, then the access token. Without such an endpoint the grant is only deleted, and the authorization server keeps it until it expires. When the revocation fails, logout says so on standard error and exits with status 0, the grant being deleted all the same (a failure to sync the directory after the delete is reported after the revocation, with status 2); revoke it at the authorization server to end it sooner.
