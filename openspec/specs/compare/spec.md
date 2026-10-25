# compare Specification

## Purpose

`mcp-gate compare` reads the catalogs that MCP endpoints serve (tools, prompts, resources and resource templates) and reports where two of them differ. It checks that a gateway serves the same catalog as another gateway or as an earlier snapshot. It needs no mcp-gate configuration, only lists, and never calls a tool, gets a prompt or reads a resource.

## Requirements

### Requirement: Sources

The command SHALL compare two sources, `-a` and `-b`, for each server named on the command line. A source whose value starts with `http://` or `https://` SHALL be an endpoint URL template that contains `{server}` in its path, where it is replaced by the path-escaped server name. Any other value SHALL be the path of a snapshot file written by `-snapshot`.

When `-a` is a snapshot and no server is named, the command SHALL compare every server in that snapshot; a snapshot without servers SHALL then be a usage error. When `-a` is an endpoint, at least one server SHALL be named. Flags SHALL come before the server names, and a server name SHALL NOT be empty, start with `-`, contain `/` or be named twice.

#### Scenario: Two endpoints

- **WHEN** `mcp-gate compare -a https://old.example.com/{server}/mcp -b https://new.example.com/{server}/mcp server-a server-b` runs
- **THEN** the catalogs of `server-a` and `server-b` are read from both endpoints and compared server by server

#### Scenario: Empty snapshot

- **WHEN** `-a` is a snapshot without servers and no server is named
- **THEN** the command exits with status 2 instead of reporting success

#### Scenario: Snapshot against an endpoint

- **WHEN** `-a` is a snapshot file and `-b` is an endpoint, and no server is named
- **THEN** every server in the snapshot is compared with the endpoint

#### Scenario: Invalid source

- **WHEN** an endpoint template lacks `{server}`, has it outside the path, or contains user information or a query string, or a server name is empty, starts with `-`, contains `/` or is named twice
- **THEN** the command exits with status 2 before connecting anywhere

### Requirement: Tokens

Endpoint credentials SHALL be read only from environment variables named by `-a-token-env` and `-b-token-env`. A token SHALL be sent as `Authorization: Bearer <token>` only to the endpoint of its own source. A named variable that is unset or empty SHALL be a usage error, and a token flag for a snapshot source SHALL be a usage error. A token SHALL never appear in the output or in error messages.

#### Scenario: Token per endpoint

- **WHEN** `-a-token-env A_TOKEN` and `-b-token-env B_TOKEN` are given
- **THEN** requests to `-a` carry the value of `A_TOKEN`, requests to `-b` carry the value of `B_TOKEN`, and neither value is printed

#### Scenario: Rejected token

- **WHEN** an endpoint answers 401
- **THEN** the server is reported as failed, the exit status is 2, and the token does not appear in the output

#### Scenario: Missing variable

- **WHEN** the variable named by a token flag is unset or empty
- **THEN** the command exits with status 2, naming the variable but no value

### Requirement: Catalog reading

For an endpoint the command SHALL connect with the official MCP Go SDK client over streamable HTTP, negotiating the protocol version the SDK supports, and SHALL read every page of the tools, prompts, resources and resource templates lists. A list whose capability the server does not advertise SHALL be read as empty; the `resources` capability covers both resources and resource templates, and an error on either list fails the server. The client SHALL advertise no client capabilities. Each server SHALL be read from each source within the `-timeout` duration (default 30s); a read that takes longer fails the server.

#### Scenario: Paginated lists

- **WHEN** a server returns its tools over several pages
- **THEN** all pages are read and compared as one list

#### Scenario: Capability not advertised

- **WHEN** one server does not advertise the prompts capability and the other advertises it with an empty list
- **THEN** no difference is reported for prompts

#### Scenario: Slow server

- **WHEN** a server does not answer within `-timeout`
- **THEN** the server is reported as failed and the exit status is 2

#### Scenario: Protocol versions

- **WHEN** the same catalog is served by two endpoints that negotiate different protocol versions
- **THEN** no difference is reported

### Requirement: Normalisation and differences

Entries SHALL be identified by name (tools and prompts), `uri` (resources) and `uriTemplate` (resource templates). Each entry SHALL be compared field by field after it is decoded by the SDK and re-encoded as canonical JSON (object keys sorted), so key order and whitespace never count as differences. Values SHALL be compared as the SDK decodes them: numbers in schemas are decoded as 64-bit floating point, so `10` and `10.0` compare equal. Every field the SDK decodes SHALL be compared, `_meta` included.

For each server the command SHALL report, in sorted order, every entry present in only one source, every field that differs (with both canonical values, or `(absent)`), and every duplicate identifier within a source. A server without differences SHALL be reported on one line with its entry counts.

#### Scenario: Schema drift

- **WHEN** a tool's `inputSchema` differs between the sources
- **THEN** the output names the server, the tool and the field `inputSchema`, and shows both canonical values

#### Scenario: Missing entry

- **WHEN** a resource is listed by `-a` but not by `-b`
- **THEN** the output reports that resource as only in `a`

#### Scenario: Key order

- **WHEN** two schemas differ only in key order
- **THEN** no difference is reported

### Requirement: Exit status

The command SHALL exit with status 0 when every server was read from both sources and no difference was found, 1 when at least one difference was found and nothing failed, and 2 on a usage error or when any server could not be read. A failure on one server SHALL NOT stop the others from being compared.

#### Scenario: Drift

- **WHEN** a difference is found and every server was read
- **THEN** the exit status is 1

#### Scenario: One server unreachable

- **WHEN** one of two servers cannot be read
- **THEN** the other server is still compared and the exit status is 2

### Requirement: Snapshots

With `-snapshot <file>` the command SHALL write the catalogs that `-a` returned, as decoded by the SDK and sorted by identifier, for the compared servers to `<file>` as JSON with `"version": 1`, replacing the file atomically, and only when every server was read from `-a`. `-b` SHALL be optional when `-snapshot` is given; without `-b` the command only writes the snapshot. `-snapshot` SHALL require an endpoint for `-a`. A snapshot with another version or with unknown fields SHALL be rejected.

#### Scenario: Snapshot then compare

- **WHEN** `-snapshot old.json` is written from an endpoint and later passed as `-a old.json` against an endpoint that serves the same catalog
- **THEN** no difference is reported and the exit status is 0

#### Scenario: Partial read

- **WHEN** a server cannot be read from `-a`
- **THEN** no snapshot file is written and the exit status is 2
