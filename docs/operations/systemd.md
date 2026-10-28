# systemd

[Docs](../README.md) / [Operations](README.md) / **systemd**

mcp-gate ships two services, each with a socket unit, all in the release archives:

| Unit | Runs as | Config | State |
| --- | --- | --- | --- |
| [`packaging/systemd/mcp-gate.service`](../../packaging/systemd/mcp-gate.service) and [`mcp-gate.socket`](../../packaging/systemd/mcp-gate.socket) | system service, user `mcp-gate` | `/etc/mcp-gate/` | `/var/lib/mcp-gate/` (also the user's home) |
| [`packaging/systemd/user/mcp-gate.service`](../../packaging/systemd/user/mcp-gate.service) and [`mcp-gate.socket`](../../packaging/systemd/user/mcp-gate.socket) | user service of the account that owns the stdio servers' files | `~/.config/mcp-gate/` | `~/.local/state/mcp-gate/` |

The socket unit is optional but recommended: systemd then holds the listening socket, so a restart or an upgrade refuses no connection (see [Restarts](#restarts)). Without it the gate opens `listen.addr` itself. Both services are `Type=notify`: the gate reports ready once every server has connected, or `startupGracePeriod` has passed, so `systemctl start` and `systemctl restart` return when it serves. `systemctl reload` applies a changed `gate.yaml` without a restart (see [Reloads](#reloads)).

Pick the user unit when stdio servers keep state in someone's home (browser profiles, token caches, credentials written by a login tool); pick the system unit when every server can live under `/var/lib/mcp-gate`.

In both, the config is `gate.yaml` and the secrets are in `gate.env` next to it, a `KEY=value` file read through `EnvironmentFile=`: the client and admin tokens and every other value the config names as `${VAR}`, and `MCP_GATE_ESCROW_KEY_SHA256` (see [serve](../commands/serve.md#escrow)); a `gate.env` that still sets the deprecated `MCP_HUB_ESCROW_KEY_SHA256` works, with a warning at start. The file must exist, even if empty: a missing one stops the start with `Failed to load environment files` instead of a run of restarts over unset variables. The gate reads its state directory from `$STATE_DIRECTORY`, which systemd sets from `StateDirectory=`, so `serve` needs no `-state-dir`. Logs are JSON lines on stderr, so they go to the journal.

### Escrow key hash as a credential

Instead of `gate.env`, the escrow key hash can come from a systemd credential, which keeps it out of the environment. Put the hex hash in a root-owned file and add a drop-in (`systemctl edit mcp-gate`, or `--user`):

```ini
[Service]
LoadCredential=escrow-key-sha256:/etc/mcp-gate/escrow-key-sha256
```

and name it in the config, which expands `$CREDENTIALS_DIRECTORY` like any variable:

```yaml
escrow:
  keyHashFile: ${CREDENTIALS_DIRECTORY}/escrow-key-sha256
```

systemd gives the service a private read-only copy (mode 0400, owned by the service's user or by root), which passes the gate's checks on the file. Commands run through `systemd-run` need the same `-p LoadCredential=…` for the config to load. Remove `MCP_GATE_ESCROW_KEY_SHA256` from `gate.env`, or keep it equal: two different hashes stop the gate.

### Escrow socket

To serve the escrow API on a unix socket (see [serve](../commands/serve.md#escrow-socket)) to another account, the reader, give the socket a group that only the reader is in. With the system unit, as root:

```sh
sudo groupadd --system mcp-gate-escrow
sudo usermod -aG mcp-gate-escrow reader      # the account that reads the secrets
```

and in a drop-in:

```ini
[Service]
RuntimeDirectory=mcp-gate
ExecStartPre=+/usr/bin/chgrp mcp-gate-escrow /run/mcp-gate
ExecStartPre=+/usr/bin/chmod 2750 /run/mcp-gate
ProtectProc=default
```

```yaml
escrow:
  socket: {path: /run/mcp-gate/escrow.sock, mode: "0660", allowUIDs: [1001]}   # 1001: the reader's user ID
  tcp: false
```

systemd creates `/run/mcp-gate` before the start, owned by `mcp-gate` and writable despite `ProtectSystem=strict`, and removes it at stop. The two `+` lines run as root: they give the directory the group and the setgid bit, so the socket the gate creates in it belongs to `mcp-gate-escrow`, and mode `0660` lets the group's members connect. The reader then reads secrets without the key; another member of the group would need it. With the default mode `0600`, only the gate's user and root can connect at all. List the reader's user ID in `allowUIDs`, never `mcp-gate`'s: the stdio servers run as `mcp-gate` and can start processes outside the gate's tree. `escrow.tcp: false` keeps the API off the TCP listener.

`ProtectProc=default` undoes the unit's `ProtectProc=invisible` for this setup. Telling the reader from the gate's own descendants means walking the reader's parent processes in `/proc`, and those belong to other users (the reader, its login session, `sshd`); with `invisible` the gate cannot see them, keyless access fails closed and every request needs the key (the gate warns at start). The cost is that the gate and its stdio servers can see every process on the host and its command line, which `invisible` hid. When that is not acceptable, keep `invisible`, leave `allowUIDs` out and have the reader send the key on the socket. A `hidepid=2` mount of `/proc` has the same effect as `invisible`.

The user unit is for one account that is both the gate's user and the reader, which `allowUIDs` cannot safely list: there, leave `allowUIDs` out and use the key on the socket too (`${XDG_RUNTIME_DIR}/mcp-gate/escrow.sock`).

## Install the system unit

```sh
sudo install -m 0755 mcp-gate /usr/local/bin/mcp-gate
sudo useradd --system --user-group --home-dir /var/lib/mcp-gate --shell /usr/sbin/nologin mcp-gate
sudo install -d -o mcp-gate -g mcp-gate -m 0700 /var/lib/mcp-gate   # before anything runs with StateDirectory=
sudo install -d -m 0755 /etc/mcp-gate
sudo install -m 0640 -g mcp-gate gate.yaml /etc/mcp-gate/gate.yaml
sudo install -m 0600 gate.env /etc/mcp-gate/gate.env      # root only: systemd reads it before dropping to mcp-gate
sudo install -m 0644 packaging/systemd/mcp-gate.service packaging/systemd/mcp-gate.socket /etc/systemd/system/
sudo systemctl daemon-reload
```

`ListenStream=` in `mcp-gate.socket` must be the config's `listen.addr`; change it with `sudo systemctl edit mcp-gate.socket` (an empty `ListenStream=` line first clears the shipped one). The gate warns at start when the socket is on another address. systemd binds the socket, so the gate needs no privilege even for a port below 1024. The socket starts before the network is up; `FreeBind=yes` in the shipped unit lets it bind an address that is not configured yet, such as a LAN or VPN address. On a host where the gate already runs without the socket unit, stop `mcp-gate.service` before the first start of `mcp-gate.socket`, or the bind fails with "address in use".

Check the config with the service's environment before the first start, then start it:

```sh
sudo systemd-run --pty --quiet --uid=mcp-gate --gid=mcp-gate \
  -p EnvironmentFile=/etc/mcp-gate/gate.env -p StateDirectory=mcp-gate -p StateDirectoryMode=0700 -p UMask=0077 \
  /usr/local/bin/mcp-gate check -connect /etc/mcp-gate/gate.yaml
sudo systemctl enable --now mcp-gate.socket mcp-gate.service
journalctl -u mcp-gate -f
```

## Install the user unit

```sh
install -D -m 0755 mcp-gate ~/.local/bin/mcp-gate
install -d -m 0700 ~/.local/state/mcp-gate   # before anything runs with StateDirectory=
install -d -m 0700 ~/.config/mcp-gate
install -m 0600 gate.yaml gate.env ~/.config/mcp-gate/
install -D -m 0644 -t ~/.config/systemd/user packaging/systemd/user/mcp-gate.service packaging/systemd/user/mcp-gate.socket
systemctl --user daemon-reload
systemd-run --user --pty --quiet -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" \
  -p StateDirectory=mcp-gate -p StateDirectoryMode=0700 -p UMask=0077 \
  ~/.local/bin/mcp-gate check -connect ~/.config/mcp-gate/gate.yaml
systemctl --user enable --now mcp-gate.socket mcp-gate.service
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

`StateDirectory=mcp-gate` sets `$STATE_DIRECTORY` to the service's directory, so no `-state-dir` is needed. Create the state directory before the first such command: when it is missing and a directory of the same name already exists in another of systemd's locations, such as the configuration directory, systemd makes the state directory a symbolic link to that one, and grants and pins end up next to the config. `StateDirectoryMode=0700` and `UMask=0077` repeat the unit's settings: without them the transient unit would make the directory 0755, and files the command's children write there readable by others. A running gate picks up a new grant without a restart (see [auth](../commands/auth.md)).

## Health and logs

```sh
curl -s http://127.0.0.1:9090/_readyz
systemd-run --user --pipe --wait --quiet -p EnvironmentFile="$HOME/.config/mcp-gate/gate.env" \
  sh -c 'printf "Authorization: Bearer %s\n" "$GATE_ADMIN_TOKEN" | curl -s -H @- http://127.0.0.1:9090/_status'
journalctl -u mcp-gate -o cat | jq -cR 'fromjson? | select(.msg == "call")'     # the audit lines
journalctl -u mcp-gate -o cat | jq -cR 'fromjson? | select(.level == "ERROR" or .level == "WARN")'
```

`GATE_ADMIN_TOKEN` stands for the variable of an `admin.tokens` entry in `gate.env`; `systemd-run` reads it from the file (with `sudo` and `--uid=mcp-gate` for the system unit), and `printf`, a shell builtin, hands it to curl on stdin, so it never shows up in a process list. `fromjson?` skips the lines that are not JSON, such as a config error printed before the logger starts.

`/_readyz` is 503 `initializing` for at most `startupGracePeriod` after a start. Then it is 503 `degraded` while a server that had connected is down (`unhealthy`) or a server waits for an OAuth login (`needsLogin`; it serves nothing until someone runs `mcp-gate auth login` for it), 503 `unavailable` when no server ever connected, and 200 `ok` otherwise. A server that has never connected since the start is not named, so `ok` does not mean that every server is up: `/_status` with an `admin.tokens` token shows each server's state, last error and the end of a stdio child's stderr, and every server in it should be `ready`. The full table is in [serve](../commands/serve.md#health-and-status).

## Stopping and restarting

`KillMode=mixed` sends SIGTERM to the gate alone. The gate stops accepting connections, and for up to a second still answers requests that arrive on connections already open, each with `Connection: close`, so that a client that sends just then gets an answer rather than a closed connection. It gives calls in flight 10 seconds from the SIGTERM, then stops every server in parallel, each stdio child's process group with SIGTERM and then SIGKILL, logging a server that takes more than 15 seconds. With the default `KillMode=control-group`, systemd would signal the children at the same moment and cut off the calls the gate is finishing. `TimeoutStopSec=40s` leaves room for both phases; when the gate exits, or the timeout passes, systemd sends SIGKILL to whatever is left in the unit's cgroup.

`Restart=on-failure` restarts the gate 5 seconds after it fails; a config that does not load fails at once, so `StartLimitBurst` stops the retries after five tries in five minutes (`systemctl reset-failed mcp-gate` after fixing it).

With the socket unit, a connection made while the service is stopped starts it. To stop the gate for good, stop both: `systemctl stop mcp-gate.socket mcp-gate.service`.

### Reloads

`systemctl reload mcp-gate` sends SIGHUP (`ExecReload=`) and returns; the gate then reads `gate.yaml` again; see [serve](../commands/serve.md#reload) for what a reload changes. A config that does not load is logged (`journalctl -u mcp-gate`) and the running one stays, so check it first:

```sh
sudo systemd-run --pty --quiet --uid=mcp-gate --gid=mcp-gate -p EnvironmentFile=/etc/mcp-gate/gate.env \
  /usr/local/bin/mcp-gate check /etc/mcp-gate/gate.yaml && sudo systemctl reload mcp-gate
```

The gate reads `${VAR}` values from the environment it started with, and systemd reads `gate.env` only at the start: a new or changed token in `gate.env` needs `systemctl restart`, which with the socket unit drops no client either.

### Restarts

With `mcp-gate.socket`, `systemctl restart mcp-gate` and an upgrade (install the new binary, then restart) drop no client:

- **No refused connection.** systemd keeps the socket open while the gate restarts. The old gate stops accepting when it gets SIGTERM; connections that arrive from then on wait in the socket's queue until the new gate accepts them.
- **No failed call.** Calls in flight finish within the 10 second grace. Requests that wait in the queue, and requests that reach the new gate before their server is up again, are held until it is (at most `startupGracePeriod`) instead of being answered 503.
- **Sessions go on.** The gate keeps no session: every request is served on its own (the SDK's stateless mode) and carries what the gate needs, the token and the protocol version. A client that initialized with the old gate goes on calling the new one without initializing again, and gets no 404 for an unknown session.

The cost is the time to restart: the calls left in flight (up to 10 seconds), stopping the stdio servers, starting the gate and connecting each server again; calls made meanwhile wait for that long. A client whose own request timeout is shorter fails the call. What does not survive a restart:

| Lost | Effect |
| --- | --- |
| `subscriptions/listen` streams | End at the SIGTERM. A client that opens its stream again, as after any dropped stream, hears of later catalog changes; one that does not misses them until it reconnects. |
| Escrowed secrets | Kept in memory only; their handles no longer resolve. |
| stdio servers | Restarted with the gate, so their own state (open browser pages, caches) is gone and each costs one cold start. HTTP servers are unaffected. |
| A call longer than the grace | Cut off after 10 seconds. |

Learned protocol pins and OAuth grants stay in the state directory. Without the socket unit a restart still keeps sessions and holds early calls, but connections made while no gate listens are refused.

## Hardening and its trade-offs

Every sandboxing setting of the unit also applies to the stdio children, which may be Node, Python or a headless browser. Both units therefore leave out settings that common servers do not tolerate, and the user unit also leaves out those a user manager cannot apply:

| Setting | Why it is not set |
| --- | --- |
| `MemoryDenyWriteExecute=yes` | Breaks JIT runtimes: Node (V8), Chromium, some Python extensions |
| `RestrictNamespaces=yes` | Breaks Chromium's user-namespace sandbox |
| `PrivateNetwork`, `IPAddressDeny`, `PrivateUsers` (system unit) | Children reach their own services and hosts, and see real file owners |
| `SystemCallFilter=` | Children run arbitrary programs |
| `ProtectHome=yes`, `ProtectSystem=strict` (user unit) | Children of a user service keep state under `$HOME` |
| `PrivateDevices`, `ProtectClock`, `ProtectKernelLogs`, `CapabilityBoundingSet` (user unit) | Need privileges a user manager may not have |
| `ProtectKernelModules` (user unit) | An unprivileged user cannot load modules anyway; it fails with 218/CAPABILITIES under AppArmor-restricted user namespaces |

In a user manager, `PrivateTmp`, `ProtectSystem`, `ProtectKernelTunables` and `ProtectControlGroups` are implemented with a user namespace, so the user unit runs with an implicit `PrivateUsers=yes`: files and groups of other users show up as owned by `nobody` to the gate and its children (access itself is unchanged). Where unprivileged user namespaces are turned off, systemd cannot create the namespace at all. There, or for a child that must see real owners, turn them off in a drop-in:

```ini
[Service]
PrivateTmp=no
ProtectSystem=no
ProtectKernelTunables=no
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
