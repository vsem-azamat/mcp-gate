# config Specification

## Purpose

The mcp-gate configuration file describes the downstream MCP servers the gate connects to. It is YAML, read strictly, and holds only the keys the build implements. `mcp-gate check` validates a file, and `mcp-gate import` converts an mcp-proxy `config.json` into one, failing on any key the build does not implement.

## Requirements

### Requirement: Strict YAML

The config SHALL be one YAML document decoded strictly: an unknown key, a duplicate key, a second document and an empty file SHALL be errors. `version` SHALL be required and SHALL be `1`. Durations SHALL be strings with a unit (`30s`, `2m`) and sizes strings with a binary unit (`B`, `KiB`, `MiB`, `GiB`); a bare number SHALL be an error for both.

#### Scenario: Unknown key

- **WHEN** a server has a key the build does not implement, such as `tools`
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
- `$VAR` and `${VAR}` in string values to `${VAR}`, and any other `$` to `$$`.

A command that runs `env` with `-i`, `-u NAME`, `-C DIR` and `NAME=VALUE` before the command SHALL be unwrapped into `command`, `args`, `cwd` and `env`, the assignments winning over `env`. Names unset with `-u` SHALL be removed from `inheritEnv` when they are in its default, and otherwise dropped with a comment, since a stdio child inherits only `inheritEnv` and `env`; `-i` SHALL give `inheritEnv: []`. An `env` command line the importer does not understand SHALL be kept as it is, with a note.

`mcpProxy.version`, `mcpProxy.type: streamable-http`, `panicIfInvalid`, `autoReconnect` and a `toolFilter` with mode `allow` and an empty list SHALL be dropped with a comment, since they have no effect in mcp-gate. Every other key that changes behaviour (listen address, startup grace period, tokens, filters, logging, redaction, OAuth, the SSE transport) SHALL make the import fail with exit status 2, listing the keys by path and writing nothing to stdout. With `-partial` the config SHALL be written anyway, each dropped key listed in a comment carrying `NOT IMPLEMENTED IN THIS BUILD`, and loading SHALL reject a file with such a comment until the comments are removed. Notes and errors SHALL name keys but never values.

#### Scenario: Unimplemented keys

- **WHEN** a server has `options.authTokens` and a non-empty `toolFilter`
- **THEN** the import fails, listing both keys, and writes nothing

#### Scenario: Partial import

- **WHEN** the same config is imported with `-partial` and the output is checked
- **THEN** the output marks both keys as not implemented and `check` rejects it

#### Scenario: env wrapper

- **WHEN** a server's command is `/usr/bin/env -u SECRET -u HOME MODE=fast HOME=/srv/h notes-server --stdio`
- **THEN** the config runs `notes-server --stdio` with `env` `HOME=/srv/h` and `MODE=fast`, `inheritEnv` is the default without `HOME`, and `SECRET` is dropped with a comment

#### Scenario: No timeout

- **WHEN** a server has no `timeout`
- **THEN** it gets `callTimeout: 0s` with a comment
