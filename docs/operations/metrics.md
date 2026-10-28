# Metrics

[Docs](../README.md) / [Operations](README.md) / **Metrics**

`mcp-gate serve` serves Prometheus metrics at `/_metrics`, in the text exposition format. The endpoint is off by default, because its labels name servers, tools and tokens. The gate counts from its start whether or not the endpoint is on, so turning it on with a reload shows everything since the start, and no reload resets a counter.

## Turning it on

There are two places to serve it, and either or both can be on:

| Config | Where | Token |
| --- | --- | --- |
| `metrics.enabled: true` | `/_metrics` on `listen.addr` | an `admin.tokens` token, as for `/_status`; needs `admin.tokens` |
| `metrics.addr: 127.0.0.1:9464` | `/_metrics` on a listener of its own, which serves nothing else | none; the address must be a loopback address or `localhost` |

Use `metrics.addr` for a Prometheus on the same host, and `metrics.enabled` for a scraper elsewhere, through the same reverse proxy as the MCP routes. `metrics.addr` takes no token, so every local user and process can read it, the MCP clients and the stdio servers on the host included; leave it off where they should not see server, tool and token names. It answers 403 to a Host that is not `localhost` or a loopback address, so a web page that rebinds its name to 127.0.0.1 cannot read it. `metrics.enabled` changes with a reload; `metrics.addr` only with a restart. A `metrics.addr` that cannot be opened stops the start.

```yaml
admin:
  tokens: {scraper: "${GATE_SCRAPE_TOKEN}"}
metrics:
  enabled: true
  addr: 127.0.0.1:9464
```

## Scrape config

On the same host, without a token:

```yaml
scrape_configs:
  - job_name: mcp-gate
    static_configs:
      - targets: ["127.0.0.1:9464"]
    metrics_path: /_metrics
```

From elsewhere, with an admin token kept in a file the Prometheus user can read:

```yaml
scrape_configs:
  - job_name: mcp-gate
    scheme: https
    metrics_path: /_metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/mcp-gate-token
    static_configs:
      - targets: ["mcp.example.com"]
```

A reverse proxy in front of the gate must pass `/_metrics` and the `Authorization` header through.

## Metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `mcp_gate_build_info` | gauge | `version` | Always 1 |
| `mcp_gate_requests_total` | counter | `server`, `kind`, `name`, `token`, `outcome` | Tool calls, prompt gets and resource reads, one per `call` audit line |
| `mcp_gate_request_duration_seconds` | histogram | `server`, `kind`, `name` | Their durations, with buckets from 5 ms to 300 s |
| `mcp_gate_redactions_total` | counter | `server` | Findings replaced and files withheld in results |
| `mcp_gate_downstream_restarts_total` | counter | `server` | Connection attempts after the first, as `restarts` in `/_status`, summed over every process the server had |
| `mcp_gate_downstream_state` | gauge | `server`, `state` | 1 for the state each enabled server is in, 0 for the others |
| `mcp_gate_escrow_entries` | gauge | | Entries the escrow holds; only with the escrow on |
| `mcp_gate_escrow_stored_total` | counter | | Entries the escrow stored under a new handle; only with the escrow on |
| `mcp_gate_reloads_total` | counter | `result` | Reloads, `success` or `failure` |
| `mcp_gate_auth_failures_total` | counter | `route` | Requests answered 401 for want of an accepted token: `/<server>/mcp`, `/mcp`, `/_status`, `/_metrics`, `/_escrow/` |

The labels take the values of the `call` line: `kind` is `tool`, `prompt` or `resource`; `token` is the token's name (never its value), empty for a public server, and the names joined by commas for a request the aggregate refused before any server saw it, which has an empty `server`; `outcome` is `ok`, `tool_error`, `error`, `denied`, `unavailable`, `withheld` or `input_required` (see the `call` line in [serve](../commands/serve.md#logs)). The `state` values are those of `/_status`: `starting`, `ready`, `degraded`, `backoff`, `disabled`, `stopped` and `needs-login`.

The label values are bounded by the config and the servers' catalogs, never by what clients send. `name` is the tool or prompt name only when the server lists it and the caller's token policy does not hide it, for the first 100 names of each server and kind; any other name, such as one a client made up or one its policy hides, is counted as `(other)`, so the metrics do not tell a hidden entry from a missing one. A resource read has an empty `name`, since URIs have no bound.

## Alerts

Some useful expressions:

```promql
# a server that is not ready
max by (server) (mcp_gate_downstream_state{state="ready"}) == 0
# a server that keeps restarting
increase(mcp_gate_downstream_restarts_total[15m]) > 3
# calls that fail
sum by (server) (rate(mcp_gate_requests_total{outcome!~"ok|tool_error"}[5m]))
# someone guessing tokens
increase(mcp_gate_auth_failures_total[10m]) > 20
# a reload that did not apply
increase(mcp_gate_reloads_total{result="failure"}[1h]) > 0
```
