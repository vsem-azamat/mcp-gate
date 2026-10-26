# config Specification

## Purpose

The mcp-gate configuration file describes the downstream MCP servers the gate connects to and how `mcp-gate serve` serves them. It is YAML, read strictly, and holds only the keys the build implements. `mcp-gate check` validates a file, and `mcp-gate import` converts an mcp-proxy `config.json` into one, failing on any key the build does not implement.

## Requirements

### Requirement: Strict YAML

The config SHALL be one YAML document decoded strictly: an unknown key, a duplicate key, a second document and an empty file SHALL be errors. `version` SHALL be required and SHALL be `1`. Durations SHALL be strings with a unit (`30s`, `2m`) and sizes strings with a binary unit (`B`, `KiB`, `MiB`, `GiB`); a bare number SHALL be an error for both.

#### Scenario: Unknown key

- **WHEN** a server has a key the build does not implement, such as `sse`
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

The config SHALL have at least one server under `servers`. A server name SHALL match `[a-z0-9][a-z0-9._-]{0,62}`. Each server SHALL have exactly one of `stdio` (with a required `command`, and optional `args`, `cwd`, `env` and `inheritEnv`) and `http` (with a required `url` and optional `headers`), and MAY set `callTimeout` (default `0s`, no bound), `maxMessageBytes` (default `16MiB`, between `4KiB` and `1GiB`), `protocolVersion` (one of the versions the SDK supports), `probeInterval` (default `30s`, at least `1s`), `restart.maxBackoff` (default `30s`, between `1s` and `5m`) and `disabled`.

An `http` server MAY have an `oauth` block (see the oauth spec), whose keys are all optional: `clientID`, `clientSecret`, which SHALL need `clientID`, `redirectURL` (default `http://localhost:8090/oauth/callback`), `scopes` and `authServerMetadataURL`. With `oauth`, the server's `url`, `redirectURL` and `authServerMetadataURL` SHALL be https URLs, or http URLs on a loopback address; `scopes` SHALL be distinct, non-empty printable ASCII without spaces, quotes or backslashes; and `headers` SHALL NOT set `Authorization`.

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

#### Scenario: OAuth over plain HTTP

- **WHEN** a server with `oauth: {}` has an `http` URL on a host that is not a loopback address
- **THEN** loading fails naming `servers.<name>.http.url`

#### Scenario: OAuth defaults

- **WHEN** a server has `oauth: {}`
- **THEN** it loads, with the default redirect URL

### Requirement: Serving keys

The config MAY set `escrow.ttl` (positive, default `24h`), `escrow.maxEntries` (default 1000, at most 100000), at most one of `escrow.keyHash` (a hex SHA-256) and `escrow.keyHashFile` (an absolute path), `escrow.sourceArguments` (a list of argument names, non-empty and distinct; see the escrow spec for its default), `escrow.tcp` (default `true`; `false` SHALL need `escrow.socket`) and `escrow.socket` with a required `path` (absolute, at most 103 bytes), `allowUIDs` (distinct user IDs; default none) and `mode` (octal permission bits, at most `0777`, default `0600`), `listen.addr` (`host:port`, default `127.0.0.1:9090`), `listen.behindProxy` (default `false`), `listen.trustedProxies` (CIDRs, default `127.0.0.1/32` and `::1/128`), `listen.allowedHosts` (host names, optionally with a port), `startupGracePeriod` (positive, default `30s`), `logLevel` (`debug`, `info`, `warn` or `error`, default `info`), `auth.tokens` and `admin.tokens`. A server MAY set `tools`, `prompts` and `resources`, each with exactly one of `allow` and `deny`, lists of non-empty entries; `auth.inherit` (default `true`), `auth.tokens` and `auth.public`; `log.requests`; `redact.enabled` (default `true`), `redact.ru`, `redact.highEntropy` and `redact.disableRules`, whose entries SHALL be redaction kinds; `redact.escrow` (default `true`); `redact.escrowTTL` (positive, default `escrow.ttl`); `redact.files` with `tools` (at least one, non-empty and distinct), `roots` (at least one absolute path other than `/`, and none that is `$HOME` of the gate's environment or a directory containing it, as written or with symlinks resolved; when `$HOME` is unset or relative the check SHALL be skipped and `serve` SHALL log a warning) and `maxBytes` (default `20MiB`, between `1KiB` and `1GiB`), which SHALL need `redact.enabled`; and `forwardMeta`, a list of `_meta` keys (default empty) whose entries SHALL be non-empty and distinct and SHALL NOT be `progressToken` or a key whose prefix before `/` has a label `mcp` or `modelcontextprotocol`, which the gate sets itself.

The config MAY set `aggregate`, which turns on the aggregate endpoint (see the serving spec), with `servers`, a list of distinct names of servers in `servers` that SHALL NOT be empty (default: every server), and `log.requests`. A disabled server listed SHALL be left out of it. The name of a server the aggregate endpoint serves SHALL NOT contain `__` or end in `_`, so that a prefixed name splits one way only.

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

#### Scenario: Two key hash sources in the config

- **WHEN** the config sets both `escrow.keyHash` and `escrow.keyHashFile`
- **THEN** loading fails naming `escrow.keyHashFile`

#### Scenario: Aggregate member with the separator in its name

- **WHEN** `aggregate: {}` is set and a server is named `a__b`
- **THEN** loading fails naming `servers.a__b`, and with `aggregate: {servers: [c]}` it loads

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

`mcp-gate check <file>` SHALL load the file with the process environment and resolve the escrow key hash as `serve` does (see the escrow spec). It SHALL exit with status 0 when both succeed, printing the number of servers and a line that says whether the escrow would be on and, when it would, which source its key hash comes from (never the hash) and, with `escrow.socket`, whether the API is served on the listener and the socket or on the socket only, and 2 with every problem otherwise.

#### Scenario: Valid config

- **WHEN** a valid config with two servers, one disabled, is checked
- **THEN** the exit status is 0 and the output says 2 servers, 1 disabled

#### Scenario: Escrow source

- **WHEN** a valid config is checked with only `MCP_GATE_ESCROW_KEY_SHA256` set
- **THEN** the output says `escrow: on, key hash from MCP_GATE_ESCROW_KEY_SHA256`, and without any key hash it says `escrow: off`

### Requirement: import

`mcp-gate import <config.json>` SHALL convert an mcp-proxy config into an mcp-gate config on stdout. Keys SHALL be matched without regard to case, as mcp-proxy matched them, and two keys of one object that differ only in case SHALL be an error. The conversion SHALL map:

- `mcpProxy.name` to `name`;
- a server's `command`, `args` and `env` to `stdio`, and `url` and `headers` with `transportType: streamable-http` to `http`;
- `timeout` to `callTimeout`; a server without `timeout` SHALL get `callTimeout: 0s` with a comment that mcp-proxy had none;
- `options.disabled` to `disabled`;
- `options.pingInterval` to `probeInterval` and `options.reconnectInterval` to `restart.maxBackoff`, a server inheriting the values in `mcpProxy.options` as mcp-proxy did; values below the minimum are raised and a reconnect interval above `5m` is lowered, with a warning;
- `mcpProxy.addr` to `listen.addr` and `mcpProxy.startupGracePeriod` to `startupGracePeriod`;
- `options.authTokens` to named tokens: those of `mcpProxy.options` to `auth.tokens`, a server's own list that differs from them to its `auth.tokens` with `inherit: false`, and a server left with no token (an empty list, or none anywhere) to `auth.public: true`. Tokens written as `${VAR}` SHALL be named after the variable, lower-cased, without the prefix up to the last `_` that all of them share; when that leaves a name empty, invalid or taken twice, or a token is written out, they SHALL be named `token1`, `token2` and so on, and a written-out token SHALL be warned about;
- `options.logEnabled` to `log.requests`;
- `toolFilter`, `promptFilter` and `resourceFilter` with mode `allow` to `allow` lists and mode `block` to `deny` lists of `tools`, `prompts` and `resources`; an empty block list and an empty `toolFilter` allow list SHALL be dropped with a comment, since they filter nothing, and filters in `mcpProxy.options` SHALL be dropped with a warning, since mcp-proxy did not apply them;
- `options.redact` to `redact` with `ru: true`, since mcp-proxy always ran the Russian rules, and `highEntropy` and `disableRules`; a server whose effective options have no `redact` block SHALL get `redact.enabled: false` with a comment;
- `mcpProxy.options.redact.escrowTTL` and `escrowMaxEntries` to `escrow.ttl` and `escrow.maxEntries` (lowered to the maximum with a warning); a server's own `escrowTTL` to `redact.escrowTTL`, and a server's own `escrowMaxEntries`, which mcp-proxy did not read, SHALL be dropped with a warning;
- `fileTools`, `fileRoots` and `fileMaxBytes` of a server's effective `redact` block to `redact.files` `tools`, `roots` and `maxBytes`, a size outside the bounds moved inside them with a warning; roots that are not absolute paths, which mcp-proxy ignored, or are `/`, SHALL be dropped with a warning, and file tools left without a root, or roots without tools, SHALL be dropped with a warning, since mcp-proxy scanned nothing then;
- a streamable HTTP server's `oauth` block to `http.oauth`: `clientId` to `clientID`, `clientSecret` (warned about when written out rather than a `${VAR}`), `redirectUri` to `redirectURL`, `scopes`, and `authServerMetadataUrl` to `authServerMetadataURL`; an empty block to `oauth: {}`, with a comment naming the login command. `pkceDisabled: false` SHALL be dropped; `pkceDisabled: true` and every other key of the block SHALL be unimplemented, since mcp-gate always uses PKCE and an OAuth setting silently lost could change whom the server trusts. A redirect or metadata URL that is not https or loopback, a server URL that is not https or loopback, and a block that is not an object SHALL fail the import. A stdio server's `oauth`, which mcp-proxy ignored, SHALL be dropped with a warning;
- `$VAR` and `${VAR}` in string values to `${VAR}`, and any other `$` to `$$`.

A command that runs `env` with `-i`, `-u NAME`, `-C DIR` and `NAME=VALUE` before the command SHALL be unwrapped into `command`, `args`, `cwd` and `env`, the assignments winning over `env`. Names unset with `-u` SHALL be removed from `inheritEnv` when they are in its default, and otherwise dropped with a comment, since a stdio child inherits only `inheritEnv` and `env`; `-i` SHALL give `inheritEnv: []`. An `env` command line the importer does not understand SHALL be kept as it is, with a note.

mcp-proxy passed each request's `_meta` on as it was; the import SHALL write no `forwardMeta` and SHALL say so in a comment. `mcpProxy.version`, `mcpProxy.type: streamable-http`, `mcpProxy.baseURL` without a path, `panicIfInvalid` and `autoReconnect` SHALL be dropped with a comment, since they have no effect in mcp-gate. Every other key that changes behaviour (a `baseURL` with a path, the OAuth keys above, the SSE transport) SHALL make the import fail with exit status 2, listing the keys by path and writing nothing to stdout. With `-partial` the config SHALL be written anyway, each dropped key listed in a comment carrying `NOT IMPLEMENTED IN THIS BUILD`, and loading SHALL reject a file with such a comment until the comments are removed. Notes and errors SHALL name keys but never values.

#### Scenario: Unimplemented keys

- **WHEN** one server's `oauth` has `pkceDisabled: true` and an unknown key, and another uses the SSE transport
- **THEN** the import fails, listing the three, and writes nothing

#### Scenario: Partial import

- **WHEN** the same config is imported with `-partial` and the output is checked
- **THEN** the output marks the keys as not implemented and `check` rejects it

#### Scenario: OAuth servers

- **WHEN** one server has `oauth: {}` and another `oauth` with `authServerMetadataUrl` and `scopes`
- **THEN** the import succeeds without `-partial`, the first gets `oauth: {}` and the second `authServerMetadataURL` and `scopes`, and the output loads

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
