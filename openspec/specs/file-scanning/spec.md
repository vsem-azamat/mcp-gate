# file-scanning Specification

## Purpose

Some tools download a file to the gate's host and report its local path instead of returning its content, so its secrets would never pass through result redaction. File scanning reads the files that a server's download tools write, after their results are redacted, and withholds from the result every file that holds secrets: the path is replaced by a marker, and the file is kept in the escrow when it is on for the server and was written since the gate started. Only files under the configured roots are read, and a path only the client named only when the call wrote it (allowing for the coarse clock of inode change times), so that neither a client nor a server can make the gate read a file outside the roots, nor a client an older one, and a server cannot pull an old file into the escrow.

## Requirements

### Requirement: File tools

File scanning SHALL apply to the tools listed in a server's `redact.files.tools`, on a server whose results are redacted, and only to results that are not tool errors. It SHALL run after the result is redacted: it SHALL look for paths in the result the server returned, and withhold files from the redacted result.

#### Scenario: Other tools

- **WHEN** a tool that is not a file tool reports a path to a file with secrets
- **THEN** its result passes as redaction left it

### Requirement: Paths

The paths of a call SHALL be the absolute paths in its result as the server returned it, and in its arguments: string members named `path`, `file_path`, `filePath`, `outputPath`, `output_path`, `localPath`, `local_path`, `savedTo` or `saved_to` of the structured content, of text content that is JSON, and of the arguments, at a depth of at most 8; strings starting with `file://` (percent-decoded) among them; the URIs of resource links and embedded resources; and the path after `downloaded to`, `saved to` or `written to` in text content, quoted or starting with `/`. An unquoted path SHALL be the longest of the first 16 space-separated words of the rest of its line (up to a quote or angle bracket, and within 4096 bytes) that lies under a root as written and names a regular file, or its first word when none does. The budget SHALL be per call, however the result is split into content items: collecting paths SHALL stop as soon as more than 64 are found, the call's texts hold more than 64 such mentions in all, or more than 1024 files have been looked up for unquoted paths, so that the work stays bounded. Trailing `.`, `,` and `;` SHALL be dropped, and relative paths ignored. A call that exceeds this budget SHALL withhold its result (see Failing closed).

A path SHALL be read only when, with every symlink resolved, it lies strictly under one of `redact.files.roots` (also resolved) and names a regular file with one link; a path that only the arguments name SHALL also have had its inode changed at or after 3 seconds before the call was forwarded, a margin for the coarse clock and the timestamp granularity of inode change times. A path the result names SHALL be read whatever its age, as a tool that caches its downloads reports the same file again, also across a restart of the gate. The file SHALL be opened through its root without following a symlink, and every check SHALL run on the opened file. Any other path SHALL be passed over: it names no file this call wrote. A path that does not exist SHALL be passed over; one written under a root whose symlinks cannot be resolved for another reason (such as a directory it cannot enter) SHALL fail.

#### Scenario: Paths a caller or server cannot use

- **WHEN** a file tool names a file outside the roots, a symlink inside a root that leads out of it, a file with a second hard link, a directory or a missing file, or only its arguments name a file whose inode changed more than 3 seconds before the call was forwarded
- **THEN** none is read and the result is unchanged

#### Scenario: File written within a clock tick of the call

- **WHEN** only the arguments of a file tool name a file with secrets whose inode change time is a clock tick, or up to 3 seconds, earlier than when the call was forwarded
- **THEN** the file is scanned and withheld

#### Scenario: Ways to report a path

- **WHEN** a file tool reports a path as `Media downloaded to <path>.`, as `Downloaded to <path with spaces>` unquoted, as a `path` member of structured content, nested in a member of an object, or as a `file://` resource link
- **THEN** each file is scanned

#### Scenario: Cached download

- **WHEN** a file tool reports the path of a file with secrets that it wrote before the call
- **THEN** the file is scanned and withheld

#### Scenario: Cached download from before the gate started

- **WHEN** a file tool reports the path of a file with secrets that it wrote before the gate started
- **THEN** the file is withheld with the marker `[REDACTED:file]` and is not kept

### Requirement: Scanning

A file whose name ends in `.p12`, `.pfx`, `.jks`, `.keystore`, `.kdbx` or `.ppk` SHALL count as holding a `secret_file`. A file SHALL be scanned as text when its name marks text (`.env` files, `id_*` keys, names with `kubeconfig`, `credentials`, `secret` or `secrets`, and the extensions `pem`, `key`, `json`, `yaml`, `yml`, `toml`, `ini`, `conf`, `cfg`, `properties`, `txt`, `log`, `sh`, `xml`, `csv`, `md`, `tf` and `tfvars`) or its first 8 KiB hold no NUL and are UTF-8 (allowing a character cut at the end); any other file is binary and SHALL pass. Text SHALL be scanned with the server's redaction engine, as JSON when it is a JSON document, and the kinds found SHALL be reported. At most two files SHALL be read at once in the process.

#### Scenario: Binary file

- **WHEN** a file tool writes a JPEG that holds a password string
- **THEN** the result is unchanged

### Requirement: Withholding

A file with secrets SHALL be withheld: kept in the escrow when it is on and every path of the call was scanned, the server's `redact.escrow` is true and its inode changed at or after 3 seconds before the gate started, a moment a reload does not move (an older file is withheld without being kept), and every content block whose text, URI, embedded resource text, or `_meta` (its own or its embedded resource's, at any depth) mentions its path (as reported, cleaned or resolved, each also as redaction wrote it in this result, without keeping anything new), whose block in the server's result mentions it, or in which its path was found (also in escaped JSON text), SHALL be replaced by a text block `<marker> file_name=<name> size=<n> bytes; contains: <kinds>. The file is withheld from this conversation; the owner can release it.`, and every string of the structured content and of the result's `_meta` that mentions it, at any depth, by the marker alone, so that a schema that requires the member still validates. The marker SHALL be `[REDACTED:file #<handle>]` when the file was kept and `[REDACTED:file]` otherwise, in which case the notice SHALL end after `conversation`. The file name SHALL be redacted. The result the downstream returned SHALL NOT be modified. Each withheld file SHALL count as one redaction in the audit line.

#### Scenario: File with a password

- **WHEN** a file tool writes `DB_PASSWORD=hunter2!x` to a file under a root and reports its path in text and in structured content
- **THEN** the client sees neither the path nor the content, the text names the file and `contains: password` with a `[REDACTED:file #<handle>]` marker, the structured `path` is the marker, and the escrow returns the file's bytes for the handle

#### Scenario: Path that redaction changes

- **WHEN** a file tool writes a file with a password under a directory whose name looks like a GitHub token, and reports its path in text and as a structured `path`
- **THEN** the file is scanned and withheld: the text block is the notice and the structured `path` is the marker

#### Scenario: Without an escrow

- **WHEN** the same happens with the escrow off, or on a server with `redact.escrow: false`
- **THEN** the marker is `[REDACTED:file]`

#### Scenario: File written before a reload

- **WHEN** a file with secrets is written after the gate started, a reload more than 3 seconds later changes the server's `redact` settings, and a file tool then reports its path
- **THEN** the file is kept and the marker carries its handle

### Requirement: Failing closed

When a file that is to be scanned cannot be, the whole result SHALL be withheld, as a result that cannot be redacted is: the client gets an error saying the result was withheld, and the audit outcome is `withheld`. That covers a call over its budget of paths, mentions or lookups (see Paths), a redacted result with a different number of content blocks than the server's, a path under a root that cannot be resolved, a file under a root that cannot be opened (other than missing or a symlink) or checked, a text or credential-store file larger than `redact.files.maxBytes` (default `20MiB`; for a larger file only the first 8 KiB decide whether it is binary), a read error, a size that changes while it is read, text that is not valid UTF-8, the call ending before the file was read, and a panic. The error and the log SHALL NOT name the file's path or quote its content.

#### Scenario: Too large

- **WHEN** a file tool writes a 2600-byte log file and `maxBytes` is `1KiB`
- **THEN** the call fails with an error saying the result was withheld, and the audit outcome is `withheld`

#### Scenario: Large binary

- **WHEN** a file tool writes a video larger than `maxBytes`
- **THEN** the result is unchanged

#### Scenario: One of two files cannot be scanned

- **WHEN** a file tool reports a file with a password and a log file over `maxBytes`
- **THEN** the result is withheld and neither file is kept in the escrow

#### Scenario: Not UTF-8

- **WHEN** a file tool writes a `.txt` file in Latin-1
- **THEN** the call fails with the result withheld
