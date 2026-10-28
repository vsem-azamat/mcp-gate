# tool-pins Specification

## Purpose

A server could change a tool's description or schema after the owner has looked at it, to steer the model (a "rug pull"). The gate pins the definition of every tool a server lists, warns when the server lists another one, and, when the server's `toolPins` is `hold`, hides a changed or new tool until the owner accepts it with `mcp-gate toolpins accept`.

## Requirements

### Requirement: Pinned definitions

The definition of a tool SHALL be everything the gate serves of it: its `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons` and `_meta`, as the server lists it. Its hash SHALL be the SHA-256 of its canonical JSON (object keys sorted, no insignificant space), written `sha256:<hex>`, so that key order and spacing do not change it. A tool name the server lists more than once SHALL count once, as first listed, for the pins and for the catalog alike, and the others SHALL be logged, so that a later entry of the same name cannot stand in for the one served.

With a server's `toolPins` set to `warn` (the default) or `hold`, every listing of the server's tools SHALL be compared with the server's pins, before the server's filter, so that a change of the filter neither creates nor hides a change:

- The first listing of a server that has no pins yet SHALL pin every listed tool as accepted (trust on first use), and log one line with the number pinned.
- A listed tool whose hash is its accepted pin's SHALL be served as before.
- A listed tool whose hash differs from its accepted pin is `changed`; one without an accepted pin, on a server that has pins, is `added`. Either SHALL be recorded as pending with its definition and hash, replacing an older pending one, and SHALL be reported once per hash and action for the life of the process with one `toolPin` line at warn level: `server`, `tool` (made fit for the log as a call's name is), `change` (`changed` or `added`), `pinned` (the accepted hash, empty for `added`), `listed` (the new hash) and `action` (`served` under `warn`, `held` under `hold`). This line is the audit record of the change. A server SHALL get at most 20 such lines a minute; the changes beyond that SHALL be recorded but not reported one by one, and one line SHALL say how many were left out.
- A pending definition SHALL be dropped when the server lists the accepted one again. A tool the server no longer lists SHALL be forgotten, its accepted pin included, so that when it is listed again it is `added`.
- A write of a server's pins that only replaces pending definitions with other ones SHALL be left to a later listing when the pins were written less than 10 seconds before, so that a server whose tools change on every listing does not cause a write per listing.

With `toolPins: off` the server's tools SHALL NOT be compared, and its pins SHALL be left as they are.

#### Scenario: First sight then a changed description

- **WHEN** a server with the default `toolPins` lists `echo` for the first time, and later lists `echo` with another description
- **THEN** the first listing pins `echo` without a warning; the second logs a `toolPin` line with `change` `changed` and `action` `served`, the new description is served, and the line is not repeated while the server goes on listing that description

#### Scenario: Key order

- **WHEN** a server lists a tool whose `inputSchema` has the same members in another order
- **THEN** its hash is unchanged and nothing is reported

#### Scenario: Decoy of the same name

- **WHEN** a server lists `echo` and after it an invalid tool also named `echo`, and later changes the first `echo`
- **THEN** the change is found and, under `hold`, `echo` is held

### Requirement: Held tools

Under `toolPins: hold`, a `changed` or `added` tool SHALL be left out of the server's catalog until its pending definition is accepted: it SHALL NOT be listed on the server's route, in any token's view, or on the aggregate endpoint, and a call of it SHALL fail exactly as a call of a tool the server does not have, logged with outcome `denied` and `tokenPolicy` `none`, as one the server's own filter hides. The previous definition SHALL NOT be served in its place. When the pins of a server under `hold` cannot be read, its lock cannot be taken, or the first pins of the server cannot be written, every listed tool SHALL be held and an error logged; under `warn` the tools SHALL be served and the error logged. `hold` needs a state directory: a config with a server under `hold` SHALL be refused by `serve` started without one, at the start and on a reload.

#### Scenario: Changed tool held everywhere

- **WHEN** a server under `toolPins: hold`, a member of the aggregate endpoint with a token policy for `phone` that passes `echo`, lists `echo` with a changed description
- **THEN** `echo` disappears from the server's route, from `phone`'s view and from `/mcp`, clients listening for changes are told, and a call of `echo` or `<server>__echo` fails as one of a tool the server does not have, logged `denied` with `tokenPolicy` `none`

#### Scenario: New tool held

- **WHEN** a server under `hold` that has pins lists a tool it has not listed before
- **THEN** the tool is held as `added` until it is accepted, while the other tools are served

#### Scenario: First pins not written

- **WHEN** a server under `hold` is listed for the first time and its pins cannot be written
- **THEN** every listed tool is held, on that listing and on the next ones until the pins are written

#### Scenario: Hold without a state directory

- **WHEN** `serve` runs without a state directory and its config, or a config a reload loads, sets `toolPins: hold` on a server
- **THEN** the start fails with an error naming the server, or the reload is refused and the running config kept

### Requirement: Pin store

With a state directory, a server's pins SHALL be kept in `toolpins/<server>.json` under it: a JSON document of version 1 holding, by tool name, the accepted pin and the pending definition, each with its hash and the time it was recorded. The directory SHALL be created with mode 0700 and each file written with mode 0600, to a temporary file `.tmp+<server>+<random>` in the same directory that is synced and then renamed over the old one; temporary files of the server left by a process that ended before the rename SHALL be removed at the next write. The gate and `mcp-gate toolpins` SHALL take the server's lock file `toolpins/<server>.lock` for every read-modify-write, so that neither loses the other's change, and one server's lock SHALL NOT delay another's. A file that is not version 1, or that does not parse, SHALL NOT be overwritten. Without a state directory, pins SHALL be kept in memory for the life of the process.

The gate SHALL read a server's pins again on every listing of its tools and on every reload (SIGHUP), including one whose config does not load, so that an accepted definition is served once the gate is reloaded, or at the server's next listing, without a restart of the server.

#### Scenario: Accept on a running gate

- **WHEN** a held tool's pending definition is accepted with `mcp-gate toolpins accept` and the gate gets SIGHUP
- **THEN** the tool is served with that definition and clients listening for changes, on the server's route and on `/mcp`, are told, without a restart of the server

### Requirement: toolpins command

`mcp-gate toolpins` SHALL work on the pins in a state directory (`-state-dir`, default the first directory of `$STATE_DIRECTORY`), without a config or the network; without a state directory it SHALL fail with exit status 2, and with a state directory, or a `toolpins` directory in it, that the user running it does not own it SHALL fail with exit status 2 and change nothing. A server name SHALL be checked against the form of a config server name. Tool names and texts from definitions SHALL be printed with every character a terminal does not show as itself (controls, format characters, variation selectors and other default-ignorable code points, line and paragraph separators, and the blank letters U+034F, U+115F, U+1160, U+2800, U+3164 and U+FFA0) written as `\u{XXXX}`.

- `toolpins list [server]` SHALL print, for each server with pins (or the one named), the number of accepted tools and each tool with a pending definition, with its change (`changed` or `added`), when it was listed and its hash. Exit status 0.
- `toolpins diff <server> [tool...]` SHALL print, for each pending tool (or each named one), what differs between the accepted and the pending definition, field by field: a text field as its lines and any other field as indented JSON, with removed lines marked `-` and added lines marked `+`, followed by the tool as `accept` takes it, `<tool>=<hash>`. Exit status 0 when nothing is pending, 1 when something is, 2 on an error.
- `toolpins accept <server> <tool>=<hash>...` SHALL make the pending definition of each named tool its accepted pin when its hash is the one given, and `toolpins accept -all <server>` that of every pending tool; it SHALL print what it accepted and that a reload of the gate applies it. A named tool with nothing pending, or whose pending hash is not the one given, because the server listed another definition since, SHALL fail the command with exit status 2 and accept nothing.

#### Scenario: Diff of a changed description

- **WHEN** `echo` of server `notes` is pending with a description that differs from the accepted one
- **THEN** `mcp-gate toolpins diff notes` shows `notes: echo: changed`, the `description` field with the old line marked `-` and the new one marked `+`, then `accept: echo=sha256:<hex>`, and exits with 1

#### Scenario: Definition changed after the diff

- **WHEN** the server lists another definition of `echo` after `diff` showed it, and `mcp-gate toolpins accept notes echo=<the hash diff showed>` runs
- **THEN** it fails with exit status 2 and `echo` stays pending with the new definition

#### Scenario: Accept a tool with nothing pending

- **WHEN** `mcp-gate toolpins accept notes echo=<hash> nosuch=<hash>` runs and only `echo` is pending
- **THEN** it fails with exit status 2 naming `nosuch`, and `echo` stays pending
