# systemd

[Docs](../README.md) / [Operations](README.md) / **systemd**

mcp-gate ships two units, both in the release archives:

| Unit | Runs as | Config | State |
| --- | --- | --- | --- |
| [`packaging/systemd/mcp-gate.service`](../../packaging/systemd/mcp-gate.service) | system service, user `mcp-gate` | `/etc/mcp-gate/` | `/var/lib/mcp-gate/` (also the user's home) |
| [`packaging/systemd/user/mcp-gate.service`](../../packaging/systemd/user/mcp-gate.service) | user service of the account that owns the stdio servers' files | `~/.config/mcp-gate/` | `~/.local/state/mcp-gate/` |

Pick the user unit when stdio servers keep state in someone's home (browser profiles, token caches, credentials written by a login tool); pick the system unit when every server can live under `/var/lib/mcp-gate`.

In both, the config is `gate.yaml` and the secrets are in `gate.env` next to it, a `KEY=value` file read through `EnvironmentFile=`: the client and admin tokens and every other value the config names as `${VAR}`, and `MCP_HUB_ESCROW_KEY_SHA256` (see [serve](../commands/serve.md#escrow)). The file must exist, even if empty: a missing one stops the start with `Failed to load environment files` instead of a run of restarts over unset variables. The gate reads its state directory from `$STATE_DIRECTORY`, which systemd sets from `StateDirectory=`, so `serve` needs no `-state-dir`. Logs are JSON lines on stderr, so they go to the journal.

## Install the system unit

```sh
sudo install -m 0755 mcp-gate /usr/local/bin/mcp-gate
sudo useradd --system --user-group --home-dir /var/lib/mcp-gate --shell /usr/sbin/nologin mcp-gate
sudo install -d -m 0755 /etc/mcp-gate
sudo install -m 0640 -g mcp-gate gate.yaml /etc/mcp-gate/gate.yaml
sudo install -m 0600 gate.env /etc/mcp-gate/gate.env      # root only: systemd reads it before dropping to mcp-gate
sudo install -m 0644 packaging/systemd/mcp-gate.service /etc/systemd/system/mcp-gate.service
sudo systemctl daemon-reload
```

Check the config with the service's environment before the first start, then start it:

```sh
sudo systemd-run --pty --quiet --uid=mcp-gate --gid=mcp-gate \
  -p EnvironmentFile=/etc/mcp-gate/gate.env -p StateDirectory=mcp-gate -p StateDirectoryMode=0700 -p UMask=0077 \
  /usr/local/bin/mcp-gate check -connect /etc/mcp-gate/gate.yaml
sudo systemctl enable --now mcp-gate
journalctl -u mcp-gate -f
```

## Install the user unit

```sh
install -D -m 0755 mcp-gate ~/.local/bin/mcp-gate
install -d -m 0700 ~/.config/mcp-gate
install -m 0600 gate.yaml gate.env ~/.config/mcp-gate/
install -D -m 0644 packaging/systemd/user/mcp-gate.service ~/.config/systemd/user/mcp-gate.service
systemctl --user daemon-reload
systemd-run --user --pty --quiet -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" \
  -p StateDirectory=mcp-gate -p StateDirectoryMode=0700 -p UMask=0077 \
  ~/.local/bin/mcp-gate check -connect ~/.config/mcp-gate/gate.yaml
systemctl --user enable --now mcp-gate
loginctl enable-linger "$USER"     # keep it running without a login session
journalctl --user -u mcp-gate -f
```

## Commands in the service's environment

`check -connect` and `auth` need the config to load, so they need the secrets of `gate.env`, and `auth` must write the grants into the state directory the service uses, as its user. `systemd-run --pty` runs a command that way without putting the secrets into a shell (`--user` for the user unit, `sudo … --uid=mcp-gate --gid=mcp-gate` for the system unit, as above):

```sh
systemd-run --user --pty --quiet -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" \
  -p StateDirectory=mcp-gate -p StateDirectoryMode=0700 -p UMask=0077 \
  ~/.local/bin/mcp-gate auth login ~/.config/mcp-gate/gate.yaml mail
```

`StateDirectory=mcp-gate` sets `$STATE_DIRECTORY` to the service's directory, so no `-state-dir` is needed. `StateDirectoryMode=0700` and `UMask=0077` repeat the unit's settings: without them the transient unit would make the directory 0755, and files the command's children write there readable by others. A running gate picks up a new grant without a restart (see [auth](../commands/auth.md)).

## Health and logs

```sh
curl -s http://127.0.0.1:9090/_readyz
printf 'Authorization: Bearer %s\n' "$GATE_ADMIN_TOKEN" | curl -s -H @- http://127.0.0.1:9090/_status
journalctl -u mcp-gate -o cat | jq -cR 'fromjson? | select(.msg == "call")'     # the audit lines
journalctl -u mcp-gate -o cat | jq -cR 'fromjson? | select(.level == "ERROR" or .level == "WARN")'
```

`fromjson?` skips the lines that are not JSON, such as a config error printed before the logger starts. `printf` is a shell builtin, so the token does not show up in a process list the way a `-H "Authorization: …"` argument would.

`/_readyz` is 503 `initializing` for at most `startupGracePeriod` after a start. Then it is 503 `degraded` while a server that had connected is down (`unhealthy`) or a server waits for an OAuth login (`needsLogin`; it serves nothing until someone runs `mcp-gate auth login` for it), 503 `unavailable` when no server ever connected, and 200 `ok` otherwise. A server that has never connected since the start is not named, so `ok` does not mean that every server is up: `/_status` with an `admin.tokens` token shows each server's state, last error and the end of a stdio child's stderr, and every server in it should be `ready`. The full table is in [serve](../commands/serve.md#health-and-status).

## Stopping and restarting

`KillMode=mixed` sends SIGTERM to the gate alone. The gate stops accepting connections, gives calls in flight 10 seconds, then stops every server in parallel, each stdio child's process group with SIGTERM and then SIGKILL, logging a server that takes more than 15 seconds. With the default `KillMode=control-group`, systemd would signal the children at the same moment and cut off the calls the gate is finishing. `TimeoutStopSec=40s` leaves room for both phases; when the gate exits, or the timeout passes, systemd sends SIGKILL to whatever is left in the unit's cgroup.

`Restart=on-failure` restarts the gate 5 seconds after it fails; a config that does not load fails at once, so `StartLimitBurst` stops the retries after five tries in five minutes (`systemctl reset-failed mcp-gate` after fixing it). A restart forgets every escrowed secret and reconnects every server; learned protocol pins and OAuth grants stay in the state directory.

The gate has no reload: a config change needs `systemctl restart`.

## Hardening and its trade-offs

Every sandboxing setting of the unit also applies to the stdio children, which may be Node, Python or a headless browser. Both units therefore leave out settings that common servers do not tolerate:

| Setting | Why it is not set |
| --- | --- |
| `MemoryDenyWriteExecute=yes` | Breaks JIT runtimes: Node (V8), Chromium, some Python extensions |
| `RestrictNamespaces=yes` | Breaks Chromium's user-namespace sandbox |
| `PrivateNetwork`, `IPAddressDeny`, `PrivateUsers` (system unit) | Children reach their own services and hosts, and see real file owners |
| `SystemCallFilter=` | Children run arbitrary programs |
| `ProtectHome=yes`, `ProtectSystem=strict` (user unit) | Children of a user service keep state under `$HOME` |
| `PrivateDevices`, `ProtectClock`, `ProtectKernelLogs`, `CapabilityBoundingSet` (user unit) | Need privileges a user manager may not have |

In a user manager, `PrivateTmp`, `ProtectSystem`, `ProtectKernelTunables`, `ProtectKernelModules` and `ProtectControlGroups` are implemented with a user namespace, so the user unit runs with an implicit `PrivateUsers=yes`: files and groups of other users show up as owned by `nobody` to the gate and its children (access itself is unchanged), and the unit fails with status 226/NAMESPACE on a host without unprivileged user namespaces. There, or for a child that must see real owners, turn them off in a drop-in:

```ini
[Service]
PrivateTmp=no
ProtectSystem=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=no
```

`RestrictAddressFamilies` keeps `AF_NETLINK` because Node and Chromium read the network interfaces through it. `PrivateTmp=yes` gives the gate and its children their own `/tmp`: a child that talks to another program through a socket in `/tmp` (an X11 display, another service) needs `PrivateTmp=no`. In the system unit `ProtectSystem=strict` and `ProtectHome=yes` leave only the state directory writable; a server that downloads elsewhere needs that directory in `ReadWritePaths=`. When one server needs fewer restrictions than the rest, a second gate with its own unit for that server keeps the others confined.

Change the unit with a drop-in, which survives upgrades of the shipped file:

```sh
sudo systemctl edit mcp-gate
# [Service]
# ReadWritePaths=/srv/downloads
# PrivateTmp=no
```

`systemd-analyze security mcp-gate` shows what is left exposed. The gate itself makes its process non-dumpable and becomes a child subreaper at start, and raises its stdio children's OOM score; none of these needs a privilege.
