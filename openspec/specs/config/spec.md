# config Specification

## Purpose

The mcp-gate configuration file describes the downstream MCP servers the gate connects to and how `mcp-gate serve` serves them. It is YAML, read strictly, and holds only the keys the build implements. `mcp-gate check` validates a file, and `mcp-gate import` converts an mcp-proxy `config.json` into one, failing on any key the build does not implement.

## Requirements

### Requirement: Strict YAML

The config SHALL be one YAML document decoded strictly: an unknown key, a duplicate key, a second document and an empty file SHALL be errors. `version` SHALL be required and SHALL be `1`. Durations SHALL be strings with a unit (`30s`, `2m`) and sizes strings with a binary unit (`B`, `KiB`, `MiB`, `GiB`); a bare number SHALL be an error for both.

#### Scenario: Unknown key

- **WHEN** a server has a key the build does not implement, such as `oauth`
- **THEN** loading fails and names the key

#### Scenario: Bare number

- **WHEN** `callTimeout: 30` is written without a unit
- **THEN** loading fails

### Requirement: Variable expansion

After decoding, every string value SHALL be expanded: `${NAME}` SHALL be replaced by the value of the environment variable `NAME` and `$$` by a literal `$`; any other `$` SHALL be kept. A variable that is unset or empty, an unterminated `${` and an invalid name SHALL be errors. Map keys SHALL NOT be expanded. Because expansion runs on decoded values, a variable's value SHALL never change the structure of the config.

#### Scenario: Secret from the environment

- **WHEN** a header value is `${SHOP_KEY}` and `SHOP_KEY` is set
- **THEN** the header carries the variable's value

#### Scenario: Unset variable

- **WHEN** a value names a variable that is unset or empty
- **THEN** loading fails, naming the field and the variable but no value

#### Scenario: Value with YAML in it

- **WHEN** a variable's value contains a line break and `disabled: true`
- **THEN** it stays one string value and no key is added

### Requirement: Servers

The config SHALL have at least one server under `servers`. A server name SHALL match `[a-z0-9][a-z0-9._-]{0,62}`. Each server SHALL have exactly one of `stdio` (with a required `command`, and optional `args`, `cwd`, `env` and `inheritEnv`) and `http` (with a required `url` and optional `headers`), and MAY set `callTimeout` (default `0s`, no bound), `maxMessageBytes` (default `16MiB`, between `4KiB` and `1GiB`), `protocolVersion` (one of the versions the SDK supports), `probeInterval` (default `30s`, at least `1s`), `restart.maxBackoff` (default `30s`, at least `1s`) and `disabled`.

`cwd` SHALL be an absolute path and `env` names valid variable names. `inheritEnv` entries SHALL be variable names, optionally ending in `*` to match a prefix; left out, it SHALL default to `PATH HOME LANG LC_* TZ USER XDG_RUNTIME_DIR`, and an empty list SHALL inherit nothing. The `url` SHALL be an absolute `http` or `https` URL without user information or a fragment. `headers` SHALL NOT set a header that mcp-gate, its HTTP client or a proxy sets (`Accept`, `Accept-Encoding`, `Content-Type`, `Content-Length`, `Host`, `Last-Event-ID`, `Proxy-Authorization`, the hop-by-hop headers and every header starting with `Mcp-`), nor one header twice in different letter case.

#### Scenario: Two transports

- **WHEN** a server has both `stdio` and `http`
- **THEN** loading fails

#### Scenario: Credentials in the URL

- **WHEN** a server's `url` contains a user and password
- **THEN** loading fails without quoting the URL

#### Scenario: Reserved header

- **WHEN** `headers` sets `Accept-Encoding`
- **THEN** loading fails

### Requirement: Serving keys

The config MAY set `escrow.ttl` (positive, default `24h`) and `escrow.maxEntries` (default 1000, at most 100000), `listen.addr` (`host:port`, default `127.0.0.1:9090`), `listen.behindProxy` (default `false`), `listen.trustedProxies` (CIDRs, default `127.0.0.1/32` and `::1/128`), `listen.allowedHosts` (host names, optionally with a port), `startupGracePeriod` (positive, default `30s`), `logLevel` (`debug`, `info`, `warn` or `error`, default `info`), `auth.tokens` and `admin.tokens`. A server MAY set `tools`, `prompts` and `resources`, each with exactly one of `allow` and `deny`, lists of non-empty entries; `auth.inherit` (default `true`), `auth.tokens` and `auth.public`; `log.requests`; `redact.enabled` (default `true`), `redact.ru`, `redact.highEntropy` and `redact.disableRules`, whose entries SHALL be redaction kinds; `redact.escrowTTL` (positive, default `escrow.ttl`); `redact.files` with `tools` (at least one, non-empty and distinct), `roots` (at least one absolute path other than `/`) and `maxBytes` (default `20MiB`, between `1KiB` and `1GiB`), which SHALL need `redact.enabled`; and `forwardMeta`, a list of `_meta` keys (default empty) whose entries SHALL be non-empty and distinct and SHALL NOT be `progressToken` or a key whose prefix before `/` has a label `mcp` or `modelcontextprotocol`, which the gate sets itself.

Tokens SHALL be maps from a name matching `[a-z0-9][a-z0-9._-]{0,62}` to a non-empty value without spaces or control characters. Every server that is not `public` SHALL accept at least one token, from `auth.tokens` (unless `inherit` is `false`) or its own; `public` SHALL exclude `tokens` and `inherit`. With `inherit`, a server's own token names SHALL differ from the global ones, and no two tokens a server accepts SHALL have the same value.

#### Scenario: Server without a token

- **WHEN** no `auth.tokens` are set and a server has neither its own tokens nor `public: true`
- **THEN** loading fails naming `servers.<name>.auth`

#### Scenario: Filter with both lists

- **WHEN** a server's `tools` sets both `allow` and `deny`
- **THEN** loading fails naming `servers.<name>.tools`

#### Scenario: Reserved meta key

- **WHEN** a server's `forwardMeta` lists `progressToken` or `io.modelcontextprotocol/clientInfo`
- **THEN** loading fails naming `servers.<name>.forwardMeta[<i>]`

#### Scenario: Shared token value

- **WHEN** two tokens a server accepts have the same value
- **THEN** loading fails naming both tokens and neither value

### Requirement: Errors

A YAML syntax or type error SHALL be reported with its line. Every expansion and validation problem SHALL be reported at once, each with its field path, such as `servers.notes.stdio.cwd`. No error SHALL quote a value, since values may be credentials.

#### Scenario: Type error

- **WHEN** `disabled` holds a word that is not a boolean
- **THEN** loading fails, naming the line but not the word

#### Scenario: Several problems

- **WHEN** one server has an invalid URL and another a relative `cwd`
- **THEN** both are reported, by path, and neither value appears

### Requirement: check

`mcp-gate check <file>` SHALL load the file with the process environment and exit with status 0 when it is valid, printing the number of servers, and 2 with every problem otherwise.

#### Scenario: Valid config

- **WHEN** a valid config with two servers, one disabled, is checked
- **THEN** the exit status is 0 and the output says 2 servers, 1 disabled

### Requirement: import

`mcp-gate import <config.json>` SHALL convert an mcp-proxy config into an mcp-gate config on stdout. Keys SHALL be matched without regard to case, as mcp-proxy matched them, and two keys of one object that differ only in case SHALL be an error. The conversion SHALL map:

- `mcpProxy.name` to `name`;
- a server's `command`, `args` and `env` to `stdio`, and `url` and `headers` with `transportType: streamable-http` to `http`;
- `timeout` to `callTimeout`; a server without `timeout` SHALL get `callTimeout: 0s` with a comment that mcp-proxy had none;
- `options.disabled` to `disabled`;
- `options.pingInterval` to `probeInterval` and `options.reconnectInterval` to `restart.maxBackoff`, a server inheriting the values in `mcpProxy.options` as mcp-proxy did;
- `mcpProxy.addr` to `listen.addr` and `mcpProxy.startupGracePeriod` to `startupGracePeriod`;
- `options.authTokens` to named tokens: those of `mcpProxy.options` to `auth.tokens`, a server's own list that differs from them to its `auth.tokens` with `inherit: false`, and a server left with no token (an empty list, or none anywhere) to `auth.public: true`. Tokens written as `${VAR}` SHALL be named after the variable, lower-cased, without the prefix up to the last `_` that all of them share; when that leaves a name empty, invalid or taken twice, or a token is written out, they SHALL be named `token1`, `token2` and so on, and a written-out token SHALL be warned about;
- `options.logEnabled` to `log.requests`;
- `toolFilter`, `promptFilter` and `resourceFilter` with mode `allow` to `allow` lists and mode `block` to `deny` lists of `tools`, `prompts` and `resources`; an empty block list and an empty `toolFilter` allow list SHALL be dropped with a comment, since they filter nothing, and filters in `mcpProxy.options` SHALL be dropped with a warning, since mcp-proxy did not apply them;
- `options.redact` to `redact` with `ru: true`, since mcp-proxy always ran the Russian rules, and `highEntropy` and `disableRules`; a server whose effective options have no `redact` block SHALL get `redact.enabled: false` with a comment;
- `mcpProxy.options.redact.escrowTTL` and `escrowMaxEntries` to `escrow.ttl` and `escrow.maxEntries` (lowered to the maximum with a warning); a server's own `escrowTTL` to `redact.escrowTTL`, and a server's own `escrowMaxEntries`, which mcp-proxy did not read, SHALL be dropped with a warning;
- `fileTools`, `fileRoots` and `fileMaxBytes` of a server's effective `redact` block to `redact.files` `tools`, `roots` and `maxBytes`, a size outside the bounds moved inside them with a warning; roots that are not absolute paths, which mcp-proxy ignored, or are `/`, SHALL be dropped with a warning, and file tools left without a root, or roots without tools, SHALL be dropped with a warning, since mcp-proxy scanned nothing then;
- `$VAR` and `${VAR}` in string values to `${VAR}`, and any other `$` to `$$`.

A command that runs `env` with `-i`, `-u NAME`, `-C DIR` and `NAME=VALUE` before the command SHALL be unwrapped into `command`, `args`, `cwd` and `env`, the assignments winning over `env`. Names unset with `-u` SHALL be removed from `inheritEnv` when they are in its default, and otherwise dropped with a comment, since a stdio child inherits only `inheritEnv` and `env`; `-i` SHALL give `inheritEnv: []`. An `env` command line the importer does not understand SHALL be kept as it is, with a note.

mcp-proxy passed each request's `_meta` on as it was; the import SHALL write no `forwardMeta` and SHALL say so in a comment. `mcpProxy.version`, `mcpProxy.type: streamable-http`, `mcpProxy.baseURL` without a path, `panicIfInvalid` and `autoReconnect` SHALL be dropped with a comment, since they have no effect in mcp-gate. Every other key that changes behaviour (a `baseURL` with a path, OAuth, the SSE transport) SHALL make the import fail with exit status 2, listing the keys by path and writing nothing to stdout. With `-partial` the config SHALL be written anyway, each dropped key listed in a comment carrying `NOT IMPLEMENTED IN THIS BUILD`, and loading SHALL reject a file with such a comment until the comments are removed. Notes and errors SHALL name keys but never values.

#### Scenario: Unimplemented keys

- **WHEN** one server has `oauth` and another uses the SSE transport
- **THEN** the import fails, listing both, and writes nothing

#### Scenario: Partial import

- **WHEN** the same config is imported with `-partial` and the output is checked
- **THEN** the output marks both keys as not implemented and `check` rejects it

#### Scenario: Escrow and file keys

- **WHEN** `mcpProxy.options.redact` has `escrowTTL: "2h"` and a server's own `redact` has `escrowTTL`, `fileTools` and `fileRoots` with one absolute and one relative root
- **THEN** the config gets `escrow.ttl: 2h`, the server its `redact.escrowTTL` and `redact.files` with the absolute root, and a warning names the dropped root

#### Scenario: env wrapper

- **WHEN** a server's command is `/usr/bin/env -u SECRET -u HOME MODE=fast HOME=/srv/h notes-server --stdio`
- **THEN** the config runs `notes-server --stdio` with `env` `HOME=/srv/h` and `MODE=fast`, `inheritEnv` is the default without `HOME`, and `SECRET` is dropped with a comment

#### Scenario: Tokens and filters

- **WHEN** `mcpProxy.options.authTokens` is `["${HUB_TOKEN_LAPTOP}", "${HUB_TOKEN_PHONE}"]`, one server has its own `["${HUB_TOKEN_MAIL}"]` and another a `toolFilter` with mode `block`
- **THEN** `auth.tokens` holds `laptop` and `phone`, the first server gets `inherit: false` and its token `mail`, and the second a `tools.deny` list

#### Scenario: No timeout

- **WHEN** a server has no `timeout`
- **THEN** it gets `callTimeout: 0s` with a comment
