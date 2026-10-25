package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/compare"
)

const compareUsage = `Usage: mcp-gate compare [flags] [server...]

Compares the catalogs (tools, prompts, resources, resource templates) that two sources serve for
each named server. Flags go before the server names. A source is an endpoint URL template containing {server}, such as
https://mcp.example.com/{server}/mcp, or a snapshot file written by -snapshot. With a snapshot as
-a and no server named, every server in the snapshot is compared.

Exit status: 0 no differences, 1 differences found, 2 usage error or a server could not be read.

Flags:
`

const defaultCompareTimeout = 30 * time.Second

// sourceFlags are the flags that describe one side of the comparison.
type sourceFlags struct {
	side     compare.Side
	arg      string
	tokenEnv string
}

// open turns the flags into a source. A snapshot source also returns the snapshot.
func (f sourceFlags) open(env lookupEnv) (compare.Source, *compare.Snapshot, error) {
	if !compare.IsEndpoint(f.arg) {
		if f.tokenEnv != "" {
			return nil, nil, fmt.Errorf("-%s-token-env is set, but -%s is a snapshot file", f.side, f.side)
		}
		s, err := compare.ReadSnapshot(f.arg)
		if err != nil {
			return nil, nil, fmt.Errorf("-%s: %w", f.side, err)
		}
		return s, s, nil
	}
	var token string
	if f.tokenEnv != "" {
		v, ok := env(f.tokenEnv)
		if !ok || v == "" {
			return nil, nil, fmt.Errorf("-%s-token-env: environment variable %s is unset or empty", f.side, f.tokenEnv)
		}
		token = v
	}
	e, err := compare.NewEndpoint(f.arg, token)
	if err != nil {
		return nil, nil, fmt.Errorf("-%s: %w", f.side, err)
	}
	return e, nil, nil
}

// compareCmd is one run of the compare command.
type compareCmd struct {
	a, b     compare.Source // b is nil when only a snapshot is written
	servers  []string
	snapshot string
	timeout  time.Duration
	stdout   io.Writer
	stderr   io.Writer
}

func runCompare(ctx context.Context, args []string, env lookupEnv, stdout, stderr io.Writer) int {
	c, code := parseCompare(args, env, stdout, stderr)
	if c == nil {
		return code
	}
	return c.run(ctx)
}

// parseCompare checks the arguments. It returns nil and an exit code when the command must not
// run.
func parseCompare(args []string, env lookupEnv, stdout, stderr io.Writer) (*compareCmd, int) {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), compareUsage)
		fs.PrintDefaults()
	}
	a := sourceFlags{side: compare.SideA}
	b := sourceFlags{side: compare.SideB}
	fs.StringVar(&a.arg, "a", "", "first source: endpoint URL template or snapshot file (required)")
	fs.StringVar(&b.arg, "b", "", "second source: endpoint URL template or snapshot file (optional with -snapshot)")
	fs.StringVar(&a.tokenEnv, "a-token-env", "", "environment variable holding the bearer token for -a")
	fs.StringVar(&b.tokenEnv, "b-token-env", "", "environment variable holding the bearer token for -b")
	snapshot := fs.String("snapshot", "", "write the catalogs read from -a to this file")
	timeout := fs.Duration("timeout", defaultCompareTimeout, "time allowed for reading one server from one source")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, exitOK
		}
		return nil, exitUsage
	}
	usageErr := func(format string, args ...any) (*compareCmd, int) {
		_, _ = fmt.Fprintf(stderr, "mcp-gate compare: "+format+"\n", args...)
		return nil, exitUsage
	}

	switch {
	case a.arg == "":
		return usageErr("-a is required")
	case b.arg == "" && *snapshot == "":
		return usageErr("-b is required unless -snapshot is given")
	case b.arg == "" && b.tokenEnv != "":
		return usageErr("-b-token-env is set without -b")
	case *snapshot != "" && !compare.IsEndpoint(a.arg):
		return usageErr("-snapshot needs an endpoint for -a")
	case *timeout <= 0:
		return usageErr("-timeout must be positive")
	}
	c := &compareCmd{snapshot: *snapshot, timeout: *timeout, stdout: stdout, stderr: stderr}
	var snapA *compare.Snapshot
	var err error
	if c.a, snapA, err = a.open(env); err != nil {
		return usageErr("%v", err)
	}
	if b.arg != "" {
		if c.b, _, err = b.open(env); err != nil {
			return usageErr("%v", err)
		}
	}
	c.servers = fs.Args()
	if len(c.servers) == 0 {
		if snapA == nil {
			return usageErr("name at least one server")
		}
		c.servers = snapA.ServerNames()
		if len(c.servers) == 0 {
			return usageErr("-a: the snapshot has no servers")
		}
	}
	seen := make(map[string]bool, len(c.servers))
	for _, s := range c.servers {
		if !compare.ValidServerName(s) {
			return usageErr("invalid server name %q (flags go before the server names)", s)
		}
		if seen[s] {
			return usageErr("server %q is named twice", s)
		}
		seen[s] = true
	}
	return c, exitOK
}

func (c *compareCmd) run(ctx context.Context) int {
	failed, drift, failedA := false, false, false
	read := map[string]compare.Catalog{}
	for _, server := range c.servers {
		ca, okA := c.read(ctx, compare.SideA, c.a, server)
		if okA {
			read[server] = ca
		} else {
			failedA = true
		}
		if c.b == nil {
			if okA {
				_, _ = fmt.Fprintf(c.stdout, "%s: read %s\n", server, ca.Counts())
			} else {
				failed = true
			}
			continue
		}
		cb, okB := c.read(ctx, compare.SideB, c.b, server)
		if !okA || !okB {
			failed = true
			continue
		}
		diffs, err := compare.Diff(ca, cb)
		if err != nil {
			_, _ = fmt.Fprintf(c.stderr, "mcp-gate compare: %s: %v\n", server, err)
			failed = true
			continue
		}
		if len(diffs) == 0 {
			_, _ = fmt.Fprintf(c.stdout, "%s: identical (%s)\n", server, ca.Counts())
			continue
		}
		drift = true
		for _, d := range diffs {
			_, _ = fmt.Fprintf(c.stdout, "%s: %s\n", server, d)
		}
	}

	if c.snapshot != "" {
		if failedA {
			_, _ = fmt.Fprintf(c.stderr, "mcp-gate compare: snapshot not written: not every server was read from -a\n")
			failed = true
		} else if err := compare.WriteSnapshot(c.snapshot, read); err != nil {
			_, _ = fmt.Fprintf(c.stderr, "mcp-gate compare: write snapshot: %v\n", err)
			failed = true
		} else {
			_, _ = fmt.Fprintf(c.stdout, "snapshot of %d servers written to %s\n", len(read), c.snapshot)
		}
	}

	switch {
	case failed:
		return exitTrouble
	case drift:
		return exitDrift
	default:
		return exitOK
	}
}

// read reads one server from one source within the timeout and reports a failure on stderr.
func (c *compareCmd) read(ctx context.Context, side compare.Side, src compare.Source, server string) (compare.Catalog, bool) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cat, err := src.Catalog(ctx, server)
	if err != nil {
		_, _ = fmt.Fprintf(c.stderr, "mcp-gate compare: %s: %s: %v\n", server, side, err)
		return compare.Catalog{}, false
	}
	return cat, true
}
