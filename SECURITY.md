# Security Policy

mcp-gate sits between MCP clients and the servers behind it, holding their tokens and secrets. Reports about that boundary are welcome.

## Reporting

Report a vulnerability privately through [GitHub's private vulnerability reporting](https://github.com/vsem-azamat/mcp-gate/security/advisories/new). Do not open a public issue, pull request or discussion for it.

Include the `mcp-gate version` output, the platform, and the smallest config and steps that show the problem. Replace every real token, secret, hostname and grant with a placeholder.

## Supported Versions

Only the latest release gets fixes. Check that the problem is still there in it before reporting.

## In Scope

- A token, secret or tool argument reaching a client, a log line or an error message unredacted: client and admin tokens, downstream credentials, OAuth grants, values from the environment.
- A way around redaction: a secret-shaped value in a result, error or notification that passes through.
- A way around client authentication or the Host check.
- Reading or releasing escrowed secrets without the escrow key.
- A way around file scanning: a file a download tool writes reaching the client without being scanned, or being read outside the configured roots.

## Out Of Scope

- Anything that needs control of the machine, the account the gate runs as, its config, its environment file or its state directory.
- What a downstream MCP server does with the requests it is sent, and secrets it returns in a form the redaction rules are not meant to recognise.
- Denial of service by a client that holds a valid token.
- Findings from scanners without a working way to exploit them, and vulnerabilities in dependencies that mcp-gate does not reach (`make vuln` reports those).
