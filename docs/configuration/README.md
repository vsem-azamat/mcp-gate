# Configuration

[Docs](../README.md) / **Configuration**

mcp-gate reads one YAML file. The behaviour is specified in [`openspec/specs/config/spec.md`](../../openspec/specs/config/spec.md); this page is the reference. `mcp-gate check <file>` validates a file (see [check](../commands/check.md)), and `mcp-gate import` writes one from an mcp-proxy `config.json` (see [import](../commands/import.md)).

The schema holds only what this build implements, so an unknown key is an error rather than a setting that is silently ignored. So far only `mcp-gate check` reads the file; no command connects to the servers yet.

## Example

```yaml
version: 1
name: mcp-gate
servers:
  notes:
    stdio:
      command: /usr/bin/node
      args: [server.js]
      cwd: /srv/notes
      env: {NOTES_DB: /srv/notes/db, NOTES_TOKEN: "${NOTES_TOKEN}"}
      inheritEnv: [PATH, HOME, LANG]
    callTimeout: 3m
  shop:
    http:
      url: https://shop.example.com/mcp
      headers: {X-Api-Key: "${SHOP_KEY}"}
    callTimeout: 2m
    maxMessageBytes: 8MiB
    protocolVersion: "2025-11-25"
    disabled: true
```

## Keys

| Key | Default | Meaning |
| --- | --- | --- |
| `version` | required | Always `1` |
| `name` | `mcp-gate` | Client name sent to the servers |
| `servers.<name>` | | One downstream server. The name is lower-case letters, digits, `.`, `_` and `-`, up to 63 characters, and becomes the path `/<name>/mcp` |
| `stdio.command` | required | Program to start, without a shell; a name without `/` is looked up in the gate's `PATH` |
| `stdio.args` | none | Its arguments |
| `stdio.cwd` | the gate's | Absolute working directory |
| `stdio.env` | none | Variables set for the child; they win over inherited ones |
| `stdio.inheritEnv` | `PATH HOME LANG LC_* TZ USER XDG_RUNTIME_DIR` | The gate's variables the child inherits; `*` at the end matches a prefix; `[]` inherits nothing |
| `http.url` | required | Streamable HTTP endpoint, `http` or `https`, without user information or fragment |
| `http.headers` | none | Headers sent with every request, such as an API key. Headers mcp-gate sets (`Accept`, `Accept-Encoding`, `Content-Type`, every `Mcp-` header and the like) cannot be set |
| `callTimeout` | `0s` | Bound on each request; `0s` is none |
| `maxMessageBytes` | `16MiB` | Largest stdio frame, HTTP response body or event, `4KiB` to `1GiB` |
| `protocolVersion` | none | Pin the protocol version offered to the server |
| `probeInterval` | `30s` | Time between liveness probes, at least `1s` |
| `restart.maxBackoff` | `30s` | Longest wait between restarts, at least `1s` |
| `disabled` | `false` | Never start the server |

Each server has exactly one of `stdio` and `http`.

## Values

- Durations are strings with a unit: `500ms`, `30s`, `2m`, `1h`. Sizes are strings with a binary unit: `512KiB`, `16MiB`. A bare number is rejected.
- `${NAME}` in any string value is replaced by the environment variable `NAME`; an unset or empty variable is an error. `$$` is a literal `$`; any other `$` is kept. Expansion happens after the YAML is parsed, so a value can never add keys.
- Secrets belong in the environment (for example a systemd `EnvironmentFile=`), referenced with `${NAME}`.

Errors name the field, such as `servers.notes.stdio.cwd: must be an absolute path`, and never print values.
