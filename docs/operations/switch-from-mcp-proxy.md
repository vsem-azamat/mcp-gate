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

Paths are those of the user unit (`~/.config/mcp-gate/`, `~/.local/state/mcp-gate/`); for the system unit they are `/etc/mcp-gate/` and `/var/lib/mcp-gate/` (see [systemd](systemd.md)). Run every step as the user mcp-proxy runs as, so that stdio servers find their files.

## 1. Install the binary and the unit

Download the release archive for the host, check it against `checksums.txt`, and install `mcp-gate` and the unit as described in [systemd](systemd.md), without enabling it yet. `mcp-gate version` prints the release.

## 2. Import the config

```sh
mcp-gate import /path/to/mcp-proxy/config.json > ~/.config/mcp-gate/gate.yaml
chmod 0600 ~/.config/mcp-gate/gate.yaml
```

The notes on stderr say what changed; [import](../commands/import.md) has the whole mapping. Go through the file before the first start:

- `listen.addr`: the import copies `mcpProxy.addr`, which the proxy still holds. Set the second port, `127.0.0.1:9090`.
- Reverse proxy: set `listen.behindProxy: true`, `listen.allowedHosts` to the host names clients use (`[mcp.example.com]`), and `listen.trustedProxies` to the proxy's address if it is not the default loopback. See [Behind a reverse proxy](#behind-a-reverse-proxy).
- Tokens: the import names each client token after its variable (`${HUB_TOKEN_LAPTOP}` becomes `laptop`); the names show up in the audit log. Values do not change, so clients keep their tokens.
- Redaction: servers mcp-proxy did not redact get `redact.enabled: false`; mcp-gate redacts by default, so consider removing those lines.
- Environment: mcp-proxy children inherited the whole environment, mcp-gate children only `stdio.inheritEnv` (by default `PATH HOME LANG LC_* TZ USER XDG_RUNTIME_DIR`) and `stdio.env`. A server that needs another variable (a display, a socket path, a token) needs it listed.
- `_meta`: mcp-gate forwards no client `_meta` keys unless `forwardMeta` lists them.
- A file written with `-partial` has `NOT IMPLEMENTED IN THIS BUILD` comments; `check` rejects it until they are dealt with.

## 3. Secrets

The imported config keeps every `${VAR}` of the old one, so the gate needs the same variables. Copy the variables from mcp-proxy's environment file (or unit) into `~/.config/mcp-gate/gate.env`, mode 0600, by name: the client tokens, values the servers use, and `MCP_HUB_ESCROW_KEY_SHA256`. Keeping the same escrow key hash means the tools that release secrets keep their key. Add `admin.tokens` to the config and its variable to `gate.env` to read `/_status`.

Never paste the values into a shell command line or the config itself.

## 4. Check

```sh
systemd-run --user --pty --quiet -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" -p StateDirectory=mcp-gate \
  ~/.local/bin/mcp-gate check ~/.config/mcp-gate/gate.yaml
```

Then the same with `check -connect`, which starts every enabled server once and reports what it found (see [check](../commands/check.md)). OAuth servers report `OAuth login required` until step 6. `-connect` starts a second copy of every stdio server while mcp-proxy runs the first: a server that takes an exclusive lock (a browser profile, a single-instance database) may fail here or disturb the running one, and a server whose login is a single session may log the other copy out. Disable such servers in the side-by-side config (`disabled: true`) and compare them after the switch instead.

## 5. Run the gate beside the proxy

```sh
systemctl --user start mcp-gate
journalctl --user -u mcp-gate -o cat -f
curl -s http://127.0.0.1:9090/_readyz
```

Do not `enable` it yet. `/_readyz` answers `initializing` for at most `startupGracePeriod`, then 200 `ok` when every server is connected, or 503 `degraded` naming servers that are down in `unhealthy` and those waiting for a login in `needsLogin`. The OAuth servers stay in `needsLogin` until the next step; everything else should be `ok`. A server that does not connect shows its last error and the end of its stderr in `/_status`:

```sh
curl -s -H "Authorization: Bearer $GATE_ADMIN_TOKEN" http://127.0.0.1:9090/_status | jq '.servers | map_values({state, lastError, stderr})'
```

## 6. Log in to the OAuth servers

mcp-proxy's OAuth tokens are not imported. For each server with an `oauth` block:

```sh
systemd-run --user --pty --quiet -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" -p StateDirectory=mcp-gate \
  ~/.local/bin/mcp-gate auth login ~/.config/mcp-gate/gate.yaml mail
```

Open the printed URL in any browser, sign in, and paste the address the browser lands on (a page that does not load). The running gate connects with the new grant within `restart.maxBackoff`. `mcp-gate auth status` lists every OAuth server and exits 0 once all are logged in; `/_readyz` then drops `needsLogin`. The login registers a new OAuth client, so the authorization server sees mcp-proxy and mcp-gate as two clients; mcp-proxy's grant keeps working for the rollback unless the server allows only one.

## 7. Compare

`compare` lists the tools, prompts, resources and templates of every server on both and prints each difference (see [compare](../commands/compare.md)). mcp-proxy and the gate serve the same paths, `/<name>/mcp`, so one template per side does:

```sh
export OLD_TOKEN=… NEW_TOKEN=…     # the same client token works on both
mcp-gate compare \
  -a 'http://127.0.0.1:8080/{server}/mcp' -a-token-env OLD_TOKEN \
  -b 'http://127.0.0.1:9090/{server}/mcp' -b-token-env NEW_TOKEN \
  server-a mail …
```

Exit status 0 means no differences. Every difference is explained before moving on: a filter the import translated differently, a server that was disabled for the side-by-side run, a tool the SDK drops as invalid. Save a snapshot of the proxy with `-snapshot` for later comparisons, after it is stopped.

Then make a real call of a harmless tool on a few servers through the gate, with the client you use day to day pointed at `http://127.0.0.1:9090/<name>/mcp`, and check its `call` line in the journal.

## 8. Move the clients

With a reverse proxy in front, point its upstream at the gate and reload it; clients keep their URL and tokens. Without one, change each client's URL to the gate's address. Either way, the gate now gets the traffic while mcp-proxy still runs:

```sh
journalctl --user -u mcp-gate -o cat | jq -c 'select(.msg == "call") | {server, principal, tool, outcome}'
```

Secrets that mcp-proxy escrowed are only in its memory: handles from results the proxy returned cannot be released from the gate. Release what you still need before step 9.

## 9. Stop mcp-proxy, keep it installed

Once the gate has served real traffic for a while:

```sh
systemctl --user disable --now mcp-proxy     # its unit name on this host
systemctl --user enable mcp-gate
```

Keep mcp-proxy's binary, config, environment file and unit as they are: that is the rollback. If the gate should take the proxy's old port, change `listen.addr`, restart the gate and move the reverse proxy's upstream back, one step at a time with `/_readyz` checked in between.

## Rollback

At any point before step 9, rolling back is moving the reverse proxy's upstream (or the clients' URLs) back to `127.0.0.1:8080` and stopping the gate. After step 9:

```sh
systemctl --user disable --now mcp-gate
systemctl --user enable --now mcp-proxy
# point the reverse proxy's upstream back at 127.0.0.1:8080 and reload it, if it was moved
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $OLD_TOKEN" http://127.0.0.1:8080/server-a/mcp
```

Escrowed secrets of the gate are lost with it. mcp-proxy's OAuth tokens may have expired or been revoked meanwhile, in which case its servers need a login of their own. The gate's state directory (pins and grants) can stay for a later attempt.

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
- `allowedHosts` takes its place: MCP routes answer only these Host names (403 otherwise). The proxy must pass the client's Host through. A rule that rewrites Host to the upstream's address, which mcp-proxy needed for the same rebinding check, is no longer needed; with it, list that address instead.
- `trustedProxies` names the proxy's own address. Only `X-Forwarded-For` from those peers is believed, so the proxy must set it (most do by default) and must not pass on a value the client sent unless it trusts that client. On a shared host every local process can reach the loopback listener and name any address in `X-Forwarded-For`; the limit then slows guessing per claimed address only, and the escrow key's length is what protects it.

With Caddy, for example, a plain `reverse_proxy 127.0.0.1:9090` passes Host and sets `X-Forwarded-For`; streams need no extra setting, but `flush_interval -1` does no harm. `/_healthz`, `/_readyz` and `/_escrow/` answer on any Host, so a proxy that serves only some hosts should also decide whether to expose them.
