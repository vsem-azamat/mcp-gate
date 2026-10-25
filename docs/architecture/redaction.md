# Redaction

[Docs](../README.md) / [Architecture](README.md) / **Redaction**

Redaction replaces credentials in what downstream servers return. The behaviour is specified in [`openspec/specs/redaction/spec.md`](../../openspec/specs/redaction/spec.md). It is a library; no command uses it yet.

## Packages

| Package | Contents |
| --- | --- |
| [`internal/redact`](../../internal/redact/redact.go) | The engine: rules, `Find`, `RedactText`, `RedactString`, `RedactJSON`, the `Replacer` interface and the default `[REDACTED:<kind>]` marker |
| [`internal/redact/mcpredact`](../../internal/redact/mcpredact/mcpredact.go) | The adapter: walks the Go SDK's tool, prompt and resource results and errors, and fails closed |

`internal/redact` imports neither `net/http` nor the MCP SDK; `depguard` enforces this (see [Checks and tooling](../development/checks.md)).

## Engine

`redact.New(redact.Options{Russian, HighEntropy, DisableRules})` builds an engine. It holds no mutable state, so one engine serves any number of goroutines. Every call takes a `Replacer`, which returns the text for each finding; `redact.Marker` writes `[REDACTED:<kind>]`, and a caller that keeps the value somewhere implements its own.

A text is scanned as follows:

1. Escaped line breaks (`\n`, `\r`, `\t` written as two characters) are masked with NUL bytes of the same length, so rules see a boundary there and offsets stay valid.
2. Each enabled rule runs in priority order. A rule may be skipped by a cheap prefilter (substrings that must occur) or precheck. Its regular expression yields candidates, and an accept function may narrow a candidate, change its kind or reject it (placeholders, `PWD=/path`, plain words after a Russian label).
3. A rule's findings are merged into those of earlier rules in one linear pass; a finding that overlaps an earlier one is dropped.

`RedactString` first checks whether the text is a JSON object or array. If so, `RedactJSON` walks it byte by byte with a stack of member names, rewrites only the string values (and numbers under secret members), and copies every other byte. String values that are themselves JSON are followed up to five levels.

## Rules and priorities

The rules are in [`rules.go`](../../internal/redact/rules.go) (core and high entropy) and [`rules_ru.go`](../../internal/redact/rules_ru.go) (Russian). Each has a unique priority constant; `sortRules` orders them and panics at start-up on a duplicate, and `TestRuleOrder` pins the order. Lower numbers run first and win overlaps:

| Priority | Rules |
| --- | --- |
| 10 | Russian `логин/пароль` pair, so nothing can split its line |
| 100–250 | Vendor formats, PEM keys, `Authorization` headers, URL passwords |
| 300–330 | `.env` assignments, `key: value` pairs, CLI flags, `"key": "value"` fragments |
| 900 | High entropy |
| 910 | Russian labels |

To add a rule, give it a free priority in the right band, a kind (a new kind is added to `Kinds` automatically), a prefilter when its matches need a literal substring, and positive and negative cases in the tests. A rule's regular expression must stay linear on large input: `TestLargeInputsStayFast` and the benchmarks catch regressions.

## Adapter

`mcpredact.New(engine, maxTextBytes)` returns a `Redactor` with `CallToolResult`, `GetPromptResult`, `ReadResourceResult` and `Error`. Each copies what it changes and leaves its input untouched. Structured values (`structuredContent`, `_meta`, tool-use input) are encoded, passed through `RedactJSON` and decoded again only when something was found.

Any failure returns an error wrapping `mcpredact.ErrWithheld` and no result: an encode or decode error, an unknown content type, a text over `maxTextBytes`, or a panic, which is recovered. Error messages name the field that failed but never quote content. A redacted error hides the original from `errors.Unwrap`; `errors.Is` still sees the original's targets and `errors.As` finds a redacted `*jsonrpc.Error` with the original code.
