# Switching from mcp-proxy

[Docs](../README.md) / [Operations](README.md) / **Switching from mcp-proxy**

A runbook for replacing a running mcp-proxy with mcp-gate on the same host without a gap: the gate runs beside the proxy on a second port, is compared with it, and takes over the clients only once it serves the same catalogs. The proxy stays installed and stopped, so a rollback is a restart away.

The examples use these placeholders:

| Placeholder | Meaning |
| --- | --- |
| `127.0.0.1:8080` | Where mcp-proxy listens (`mcpProxy.addr`) |
| `127.0.0.1:9090` | Where the gate listens during and after the switch |
| `https://mcp.example.com` | The address clients use: a reverse proxy in front of mcp-proxy |
| `server-a`, `mail` | A server, and an HTTP server with an `oauth` block |
| `mcp-proxy.service` | The proxy's unit |

The runbook uses the [user unit](systemd.md), run by the account mcp-proxy runs as, so that stdio servers find their files under the same home. With the system unit, the paths are `/etc/mcp-gate/` and `/var/lib/mcp-gate/`, the commands run through `sudo systemd-run --uid=mcp-gate --gid=mcp-gate`, and the stdio servers' files must be readable by that user.

Every command that needs the gate's secrets runs through `systemd-run`, which reads `gate.env` itself, so no value goes through the shell:

```sh
gx() { # the gate's environment and state directory, interactive
  systemd-run --user --pty --quiet --same-dir -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" \
    -p StateDirectory=mcp-gate -p StateDirectoryMode=0700 -p UMask=0077 "$@"
}
```

## 1. Install the binary and the unit

Download the release archive for the host, check it against `checksums.txt`, unpack it, and install the binary and the unit without starting it:

```sh
sha256sum --ignore-missing -c checksums.txt
install -D -m 0755 mcp-gate ~/.local/bin/mcp-gate
install -D -m 0644 packaging/systemd/user/mcp-gate.service ~/.config/systemd/user/mcp-gate.service
systemctl --user daemon-reload
mcp-gate version
```

## 2. Import the config

```sh
install -d -m 0700 ~/.config/mcp-gate
(umask 077; mcp-gate import /path/to/mcp-proxy/config.json > ~/.config/mcp-gate/gate.yaml)
```

The notes on stderr say what changed; [import](../commands/import.md) has the whole mapping. Go through the file before the first start:

- `listen.addr`: the import copies `mcpProxy.addr`, which the proxy still holds. Set the second port, `127.0.0.1:9090`.
- Reverse proxy: set `listen.behindProxy`, `listen.allowedHosts` and, if the proxy is not on loopback, `listen.trustedProxies`. See [Behind a reverse proxy](#behind-a-reverse-proxy).
- Literal secrets: a token or `clientSecret` written as a value in the old config is copied as it is, with a warning. Move each into `gate.env` and reference it as `${VAR}`.
- Tokens: the import names each client token after its variable (`${HUB_TOKEN_LAPTOP}` becomes `laptop`); the names show up in the audit log. Values do not change, so clients keep their tokens.
- Redaction: servers mcp-proxy did not redact get `redact.enabled: false`; mcp-gate redacts by default, so consider removing those lines.
- Environment: mcp-proxy children inherited the whole environment, mcp-gate children only `stdio.inheritEnv` (by default `PATH HOME LANG LC_* TZ USER XDG_RUNTIME_DIR`) and `stdio.env`. A server that needs another variable (a display, a socket path, a token) needs it listed.
- `_meta`: mcp-gate forwards no client `_meta` keys unless `forwardMeta` lists them.
- A file written with `-partial` has `NOT IMPLEMENTED IN THIS BUILD` comments; `check` rejects it until they are dealt with.

## 3. Secrets

The imported config keeps every `${VAR}` of the old one, so the gate needs the same variables. Copy mcp-proxy's environment file, which keeps the values off the screen:

```sh
install -m 0600 /path/to/mcp-proxy/env-file ~/.config/mcp-gate/gate.env
printf '\nGATE_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)" >> ~/.config/mcp-gate/gate.env
```

If mcp-proxy's unit sets secrets with `Environment=` lines instead of a file, copy them into `gate.env` as `KEY=value` lines with an editor, not with `echo` on a command line.

and add `admin: {tokens: {owner: "${GATE_ADMIN_TOKEN}"}}` to the config for `/_status`. Keeping `MCP_HUB_ESCROW_KEY_SHA256` means the tools that release secrets keep their key.

## 4. Check

```sh
gx ~/.local/bin/mcp-gate check ~/.config/mcp-gate/gate.yaml
gx ~/.local/bin/mcp-gate check -connect ~/.config/mcp-gate/gate.yaml
```

`-connect` starts every enabled server once and reports what it found (see [check](../commands/check.md)); OAuth servers report `OAuth login required` until step 6. It starts a second copy of every stdio server while mcp-proxy runs the first: a server that takes an exclusive lock (a browser profile, a single-instance database) may fail here or disturb the running one, and a server whose login is a single session may log the other copy out. Set `disabled: true` on such servers for now; step 10 brings them over.

## 5. Run the gate beside the proxy

```sh
systemctl --user start mcp-gate
journalctl --user -u mcp-gate -o cat -f
curl -s http://127.0.0.1:9090/_readyz
gx sh -c 'printf "Authorization: Bearer %s\n" "$GATE_ADMIN_TOKEN" | curl -s -H @- http://127.0.0.1:9090/_status' |
  jq '.servers | map_values({state, lastError, stderr})'
```

Do not `enable` it yet. `/_readyz` answers `initializing` for at most `startupGracePeriod`, then 503 `degraded` naming the OAuth servers in `needsLogin` until step 6. It does not name a server that never connected, so go by `/_status`: every server but the OAuth ones should be `ready`; one that is not shows its last error and the end of its stderr.

## 6. Log in to the OAuth servers

mcp-proxy's OAuth tokens are not imported. For each server with an `oauth` block:

```sh
gx ~/.local/bin/mcp-gate auth login ~/.config/mcp-gate/gate.yaml mail
gx ~/.local/bin/mcp-gate auth status ~/.config/mcp-gate/gate.yaml
```

Open the printed URL in any browser, sign in, and paste the address the browser lands on (a page that does not load). The running gate connects with the new grant within `restart.maxBackoff`. `auth status` exits 0 once every OAuth server is logged in; `/_readyz` then drops `needsLogin`. The login registers a new OAuth client, so the authorization server sees mcp-proxy and mcp-gate as two clients; mcp-proxy's grant keeps working for the rollback unless the server allows only one.

## 7. Compare, and snapshot the proxy

`compare` lists the tools, prompts, resources and templates of every server on both and prints each difference (see [compare](../commands/compare.md)). mcp-proxy and the gate serve the same paths, `/<name>/mcp`, so one template per side does. The token variables are those of `gate.env`; servers with their own tokens are compared in a run of their own, with one of their tokens:

```sh
gx ~/.local/bin/mcp-gate compare \
  -a 'http://127.0.0.1:8080/{server}/mcp' -a-token-env HUB_TOKEN_LAPTOP \
  -b 'http://127.0.0.1:9090/{server}/mcp' -b-token-env HUB_TOKEN_LAPTOP \
  server-a mail
```

Exit status 0 means no differences. Explain every difference before moving on: a filter the import translated differently, a tool the SDK drops as invalid.

While the proxy still runs, save a snapshot of every server it serves, including the ones disabled in the gate, for step 10 and for later comparisons:

```sh
gx ~/.local/bin/mcp-gate compare -a 'http://127.0.0.1:8080/{server}/mcp' -a-token-env HUB_TOKEN_LAPTOP \
  -snapshot ~/.local/state/mcp-gate/proxy-snapshot.json server-a mail server-b
```

Then make a real call of a harmless tool on a few servers through the gate, with a client you use day to day pointed at `http://127.0.0.1:9090/<name>/mcp`, and check its `call` line in the journal.

## 8. Move the clients

With a reverse proxy in front, point its upstream at the gate and reload it; clients keep their URL and tokens. Servers still disabled in the gate stay on mcp-proxy: route their paths (`/server-b/mcp`) to `127.0.0.1:8080` until step 10. Without a reverse proxy, change each client's URL to the gate's address, except for those servers. mcp-proxy keeps running meanwhile.

```sh
journalctl --user -u mcp-gate -o cat | jq -cR 'fromjson? | select(.msg == "call") | {server, principal, tool, outcome}'
```

Secrets that mcp-proxy escrowed are only in its memory: handles from results the proxy returned cannot be released from the gate. Release what you still need before step 9.

## 9. Stop mcp-proxy, keep it installed

Once the gate has served real traffic for a while:

```sh
systemctl --user disable --now mcp-proxy
systemctl --user enable mcp-gate
```

Keep mcp-proxy's binary, config, environment file and unit as they are: that is the rollback.

## 10. Bring over the servers that were disabled

Between step 9 and this step those servers are served by neither, so run it straight after step 9. With mcp-proxy stopped, remove `disabled: true` from those servers, restart the gate, check them against the snapshot, and move their paths to the gate:

```sh
systemctl --user restart mcp-gate
gx ~/.local/bin/mcp-gate compare -a ~/.local/state/mcp-gate/proxy-snapshot.json \
  -b 'http://127.0.0.1:9090/{server}/mcp' -b-token-env HUB_TOKEN_LAPTOP server-b
```

The restart reconnects every server and forgets what the gate has escrowed so far: handles in earlier results can no longer be released.

If the gate should take the proxy's old port, change `listen.addr`, restart the gate and move the reverse proxy's upstream, checking `/_status` in between.

## Rollback

Before step 9, rolling back is moving the reverse proxy's upstream (or the clients' URLs) back to `127.0.0.1:8080` and stopping the gate. After it:

```sh
systemctl --user disable --now mcp-gate
systemctl --user enable --now mcp-proxy
# point the reverse proxy's upstream back at 127.0.0.1:8080 and reload it
gx ~/.local/bin/mcp-gate compare -a ~/.local/state/mcp-gate/proxy-snapshot.json \
  -b 'http://127.0.0.1:8080/{server}/mcp' -b-token-env HUB_TOKEN_LAPTOP
```

As in step 7, servers with their own tokens are compared in runs of their own. Escrowed secrets of the gate are lost with it. mcp-proxy's OAuth tokens may have expired or been revoked meanwhile, in which case its servers need a login of their own. The gate's state directory (pins and grants) can stay for a later attempt.

## Behind a reverse proxy

mcp-gate behind a reverse proxy on the same host needs three settings:

```yaml
listen:
  addr: 127.0.0.1:9090
  behindProxy: true
  allowedHosts: [mcp.example.com]
  trustedProxies: [127.0.0.1/32]     # the default, with ::1/128
```

- `behindProxy` turns off the SDK's DNS-rebinding check, which on a loopback listener answers only loopback Host names, and makes the request log and the escrow's failed-auth limit read the client's address from `X-Forwarded-For`: the right-most entry that is not in `trustedProxies`.
- `allowedHosts` takes its place: MCP routes answer only these Host names (403 otherwise). The proxy must pass the client's Host through, or rewrite it to a name in the list. mcp-proxy needed a rewrite to its loopback address for the same rebinding check; a proxy that keeps that rewrite works with `allowedHosts: [127.0.0.1, localhost]`, which also lets it point at either backend unchanged during the switch.
- `trustedProxies` names the proxy's own address. Only `X-Forwarded-For` from those peers is believed, so the proxy must set it (most do by default) and must not pass on a value the client sent unless it trusts that client. On a shared host every local process can reach the loopback listener and name any address in `X-Forwarded-For`; the limit then slows guessing per claimed address only, and the escrow key's length is what protects it.

With Caddy, for example, a plain `reverse_proxy 127.0.0.1:9090` passes Host and sets `X-Forwarded-For`; `flush_interval -1` does no harm for event streams. `/_healthz`, `/_readyz` and `/_escrow/` answer on any Host, so a proxy that serves only some hosts should also decide whether to expose them.
