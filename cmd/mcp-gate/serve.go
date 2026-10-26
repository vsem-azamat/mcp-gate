package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/procutil"
	"github.com/vsem-azamat/mcp-gate/internal/version"
)

const serveUsage = `Usage: mcp-gate serve [flags] <config.yaml>

Serves the servers of an mcp-gate config: each at /<name>/mcp on listen.addr, behind its tokens,
with /_healthz, /_readyz and, with admin tokens, /_status. With the hex SHA-256 of an API key in
escrow.keyHash, escrow.keyHashFile or MCP_GATE_ESCROW_KEY_SHA256, redacted secrets are kept in
memory and served at /_escrow/ to that key. Logs are JSON lines on stderr. SIGINT and SIGTERM
shut it down.

Exit status: 0 after a clean shutdown, 2 when the config is invalid or the gate fails.

Flags:
`

// withoutEscrowKey drops the escrow key hash variables, and the variables named in extra (those
// escrow.keyHash was expanded from), from the environment stdio children inherit from, so that
// no inheritEnv pattern hands them to a child.
func withoutEscrowKey(environ []string, extra ...string) []string {
	names := append([]string{escrow.KeyHashEnv, escrow.LegacyKeyHashEnv}, extra...)
	return slices.DeleteFunc(slices.Clone(environ), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(names, name)
	})
}

// escrowKey resolves the escrow key hash of a loaded config: nil when the escrow is off.
func escrowKey(cfg *config.Config, env lookupEnv) (*escrow.Key, error) {
	return escrow.ResolveKey(escrow.KeyConfig{Hash: cfg.Escrow.KeyHash, HashFile: cfg.Escrow.KeyHashFile}, env)
}

func runServe(ctx context.Context, args []string, env lookupEnv, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), serveUsage)
		fs.PrintDefaults()
	}
	stateDir := fs.String("state-dir", defaultStateDir(env), "directory for learned protocol pins and OAuth grants (default $STATE_DIRECTORY; empty keeps none)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "mcp-gate serve: name one config file")
		return exitUsage
	}
	cfg, err := config.Load(fs.Arg(0), config.LookupFunc(env))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate serve: %s:\n  %s\n", fs.Arg(0), strings.ReplaceAll(err.Error(), "\n", "\n  "))
		return exitUsage
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel)) // validated
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	if err := procutil.SetNonDumpable(); err != nil {
		logger.Warn("cannot make the process non-dumpable", "error", err.Error())
	}
	if r, err := procutil.EnableSubreaper(); err != nil {
		logger.Warn("cannot become a child subreaper", "error", err.Error())
	} else {
		defer r.Close()
	}
	if *stateDir == "" {
		logger.Info("no state directory: learned protocol pins are not kept across restarts, and OAuth servers cannot log in")
	}
	key, err := escrowKey(cfg, env)
	if err != nil {
		logger.Error("cannot start", "error", err.Error())
		return exitTrouble
	}
	if key != nil && key.Deprecated {
		logger.Warn(escrow.LegacyKeyHashEnv+" is deprecated; rename it "+escrow.KeyHashEnv, "keySource", key.Source)
	}
	g, err := gate.New(gate.Options{
		Config: cfg, Environ: withoutEscrowKey(parentEnviron(), cfg.Escrow.KeyHashVars...), StateDir: *stateDir, Version: version.Get().Version, Logger: logger,
		EscrowKey: key,
	})
	if err != nil {
		logger.Error("cannot start", "error", err.Error())
		return exitTrouble
	}
	ln, err := g.Listen(ctx)
	if err != nil {
		logger.Error("cannot listen", "addr", cfg.Listen.Addr, "error", err.Error())
		return exitTrouble
	}
	if err := g.Run(ctx, ln); err != nil {
		logger.Error("gate failed", "error", err.Error())
		return exitTrouble
	}
	logger.Info("stopped")
	return exitOK
}
