# Redaction

[Docs](../README.md) / [Architecture](README.md) / **Redaction**

Redaction replaces credentials in what downstream servers return. The behaviour is specified in [`openspec/specs/redaction/spec.md`](../../openspec/specs/redaction/spec.md). `mcp-gate serve` applies it to every result of a server with `redact.enabled` (see [Serving](serving.md)), and the supervisors use the engine for error messages and child stderr.

## Packages

| Package | Contents |
| --- | --- |
| [`internal/redact`](../../internal/redact/redact.go) | The engine: rules, `Find`, `RedactText`, `RedactString`, `RedactJSON`, the `Replacer` interface and the default `[REDACTED:<kind>]` marker |
| [`internal/redact/mcpredact`](../../internal/redact/mcpredact/mcpredact.go) | The adapter: walks the Go SDK's tool, prompt and resource results and errors, and fails closed |

`internal/redact` imports neither `net/http` nor the MCP SDK; `depguard` enforces this (see [Checks and tooling](../development/checks.md)).

## Engine

`redact.New(redact.Options{Russian, HighEntropy, DisableRules})` builds an engine. It holds no mutable state, so one engine serves any number of goroutines. Every call takes a `Replacer`, which returns the text for each finding; `redact.Marker{}` writes `[REDACTED:<kind>]`, and a caller that keeps the value somewhere implements its own.

A text is scanned as follows:

1. Escaped line breaks (`\n`, `\r` written as two characters) are masked with two NUL bytes and escaped tabs (`\t`) with two 0x01 bytes, so rules see a boundary there and offsets stay valid; a NUL byte already in the text becomes 0x01 first. Unquoted values still match over masked bytes, as before; `keyValueAccept` then narrows them with `narrowAtBreaks`: leading masked bytes are dropped when the rest is no placeholder, and the value ends at the first masked line break when the part before it has at least 8 characters (`minValueBeforeBreak`) and is no placeholder, both measured after the trimming of trailing punctuation and space that the value would get (`redactedAlone`). Each narrowing applies only when the narrowed value would be replaced on its own, so the rules never replace less than whole-value matching would, apart from the text after such a break.
2. Each enabled rule runs in priority order. A rule may be skipped by a cheap prefilter (substrings that must occur) or precheck, or run only over regions of the text: the next-line key-value rule ([`rules_nextline.go`](../../internal/redact/rules_nextline.go)) matches only the last 512 bytes of each line that ends with a separator and holds a key word, with the line after it, and only when that line can hold a value alone (`mayBeValueLine`: one quoted value or one run without inner space, at most 8 KiB). Each such region is matched once, so text without key lines costs it one scan for line breaks. Its regular expression yields candidates, and an accept function may narrow a candidate, change its kind or reject it (placeholders, `PWD=/path`, plain words after a Russian label).
3. A rule's findings are merged into those of earlier rules in one linear pass. Overlapping findings become one finding over their union, with the kind of the earliest rule, so that no part of either stays visible. A replacer that keeps values, such as an escrow, then keeps the merged text as one value.

`RedactString` first checks whether the text is a JSON object or array. If so, `RedactJSON` walks it byte by byte with a stack of member names, rewrites only the string values (and numbers under secret members) and the member names that hold a finding, and copies every other byte. A name is matched for the value's secret kind as written, and replaced as a string value would be. Names found clean are remembered for the rest of the document (`cleanNames`), so a list of many objects with the same members scans each name once. On the first replaced name of an object, `objectNames` collects the names written in it, and `uniqueName` appends `#2`, `#3` and so on until the replacement is not among those or the replacements already given, so that decoding into a map loses no member. Those scans share a budget of eight times the document plus 1 MiB (`namesScanFactor`, `namesScanSlack`), since nested objects with replaced names would make them quadratic; past it, names are kept apart from the replacements only (an empty `taken`), so the rewrite never fails over names and a pathological document can at worst get a duplicate name. Under a secret member, `nameShapeOf` decides whether a name is a value rather than an identifier (no `plainIdentifier`, not in `nestedSafeKeys`, and a digit, a symbol or high entropy, or only a flag as its value, which `onlyFlag` reads ahead); such a name is replaced whole with the member's kind, through the same `uniqueName`, and the shape of each name is remembered for the document (`secretNames`). String values that are themselves JSON are followed up to five levels.

Tokens split across strings are in [`split.go`](../../internal/redact/split.go). For each string literal, `adjacentString` finds the adjacent one (a name's value, the next member's value, the next element), and `splitAfter` checks the boundary: both sides must be `isSplitByte`, and the window, the run of such bytes that ends the first string and the one that starts the second (`splitWindow`, 256 bytes each), must pass `maySplit`, which looks for the prefilter words of the vendor rules (the rules marked `split`) through a table keyed by their first two bytes, or a digit and a colon, on the raw bytes of the second literal unless an escape starts its run. Only then is the second literal decoded and `splitToken` runs the split rules over the joined window, keeping a match that crosses the boundary, unless the first string is a member name and a split rule finds a whole token at its end. A value already continuing a token is not joined to its own name. The cut is applied to the first string at once and remembered for the second (`heads`, by literal offset); `redactCut` writes `ContinuationMarker` for the second part, the replacement of the whole token for the first, and the strings' own findings cut back around them. Text without such boundaries costs a look at the bytes around each string's quotes.

## Rules and priorities

The rules are in [`rules.go`](../../internal/redact/rules.go) (core and high entropy), [`rules_nextline.go`](../../internal/redact/rules_nextline.go) (the helpers of the next-line key-value rule) and [`rules_ru.go`](../../internal/redact/rules_ru.go) (Russian; its next-line label rule matches each line that ends with a label and separator, with the line after it, through `russianKeyLineRegions`, and its same-line label rule has `rescan`: `rescanSpans` goes on from the start of each candidate's value rather than its end, so a label inside a value is matched too, within a budget of four times the text plus 64 KiB of bytes read again). Each has a unique priority constant; `sortRules` orders them and panics at start-up on a duplicate, and `TestRuleOrder` pins the order. Lower numbers run first and give their kind to merged overlaps:

| Priority | Rules |
| --- | --- |
| 10 | Russian `логин/пароль` pair, so nothing can split its line |
| 100–250 | Vendor formats, PEM keys, `Authorization` headers, URL passwords |
| 300–330 | `.env` assignments, `key: value` pairs, a key at the end of a line with its value on the next one, CLI flags, `"key": "value"` fragments |
| 900 | High entropy |
| 910–920 | Russian labels, with the value on the same line or on the next one |

To add a rule, give it a free priority in the right band, a kind (a new kind is added to `Kinds` automatically), a prefilter when its matches need a literal substring, and positive and negative cases in the tests. A vendor format whose matches hold only `isSplitByte` bytes and that has a prefilter is marked `split`, so it is also matched across JSON strings. A rule's regular expression must stay linear on large input: `TestLargeInputsStayFast` and the benchmarks catch regressions.

## Adapter

`mcpredact.New(engine, maxTextBytes)` returns a `Redactor` with `CallToolResult`, `GetPromptResult`, `ReadResourceResult` and `Error`. Each copies what it changes and leaves its input untouched. Structured values (`structuredContent`, `_meta`, tool-use input) are encoded, passed through `RedactJSON` and decoded again only when something was found.

Any failure returns an error wrapping `mcpredact.ErrWithheld` and no result: an encode or decode error, an unknown content type, a text over `maxTextBytes`, a text blob over `MaxBlobBytes` (8 MiB) or not valid UTF-8 (a blob without a MIME type or with `application/octet-stream` counts as text when it is valid UTF-8 without NUL), a multi-round-trip result (input requests or request state, which are not redacted), or a panic, which is recovered. Error messages name the field that failed but never quote content. A redacted error hides the original from `errors.Unwrap`; `errors.Is` still sees the original's targets and `errors.As` finds a redacted `*jsonrpc.Error` with the original code. Only an unwrapped `*jsonrpc.Error` is returned as one, with its data; the SDK takes just the code from a wrapped one.
