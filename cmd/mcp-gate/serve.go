package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/procutil"
	"github.com/vsem-azamat/mcp-gate/internal/version"
)

const serveUsage = `Usage: mcp-gate serve [flags] <config.yaml>

Serves the servers of an mcp-gate config: each at /<name>/mcp on listen.addr, behind its tokens,
with /_healthz, /_readyz and, with admin tokens, /_status. Logs are JSON lines on stderr. SIGINT
and SIGTERM shut it down.

Exit status: 0 after a clean shutdown, 2 when the config is invalid or the gate fails.

Flags:
`

func runServe(ctx context.Context, args []string, env lookupEnv, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), serveUsage)
		fs.PrintDefaults()
	}
	stateDefault, _ := env("STATE_DIRECTORY")
	stateDefault, _, _ = strings.Cut(stateDefault, ":")
	stateDir := fs.String("state-dir", stateDefault, "directory for learned protocol pins (default $STATE_DIRECTORY; empty keeps none)")
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
		logger.Info("no state directory: learned protocol pins are not kept across restarts")
	}
	g, err := gate.New(gate.Options{
		Config: cfg, Environ: parentEnviron(), StateDir: *stateDir, Version: version.Get().Version, Logger: logger,
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
