package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/downstream"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/oauth"
	"github.com/vsem-azamat/mcp-gate/internal/procutil"
	"github.com/vsem-azamat/mcp-gate/internal/version"
)

const checkUsage = `Usage: mcp-gate check [flags] <config.yaml>

Loads and validates an mcp-gate config: strict YAML, ${VAR} expanded from the environment,
and the gate built from it as serve and a reload build it, without starting anything.
It also says whether the escrow would be on and where its key hash comes from.
With -connect it also connects to every enabled server, starting stdio servers, and reports
the protocol version and number of tools of each; then it stops them.

Exit status: 0 valid (and, with -connect, every enabled server connected), 2 otherwise.

Flags:
`

const defaultCheckTimeout = 60 * time.Second

// parentEnviron is the environment stdio children inherit from, as os.Environ returns it.
var parentEnviron = os.Environ

func runCheck(ctx context.Context, args []string, env lookupEnv, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), checkUsage)
		fs.PrintDefaults()
	}
	connect := fs.Bool("connect", false, "also connect to every enabled server")
	timeout := fs.Duration("timeout", defaultCheckTimeout, "with -connect: time allowed for each server to connect")
	verbose := fs.Bool("v", false, "with -connect: log the supervisors and child stderr to stderr")
	stateDir := fs.String("state-dir", defaultStateDir(env), "with -connect: the gate's state directory, which holds the OAuth grants (default $STATE_DIRECTORY)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "mcp-gate check: name one config file")
		return exitUsage
	}
	if *timeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "mcp-gate check: -timeout must be positive")
		return exitUsage
	}
	cfg, err := config.Load(fs.Arg(0), config.LookupFunc(env))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate check: %s:\n  %s\n", fs.Arg(0), strings.ReplaceAll(err.Error(), "\n", "\n  "))
		return exitUsage
	}
	names := make([]string, 0, len(cfg.Servers))
	disabled := 0
	for name, s := range cfg.Servers {
		names = append(names, name)
		if s.Disabled {
			disabled++
		}
	}
	sort.Strings(names)
	key, err := escrowKey(cfg, env)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate check: %s:\n  %s\n", fs.Arg(0), err)
		return exitUsage
	}
	// Built as serve and a reload build it, starting nothing, so that check accepts what they do.
	if _, err := gate.New(gate.Options{
		Config: cfg, Environ: childEnviron(parentEnviron(), cfg.Escrow.KeyHashVars...), Version: version.Get().Version, EscrowKey: key,
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate check: %s:\n  %s\n", fs.Arg(0), err)
		return exitUsage
	}
	_, _ = fmt.Fprintf(stdout, "%s: valid, %d servers (%d disabled)\n", fs.Arg(0), len(names), disabled)
	for _, w := range cfg.Warnings {
		_, _ = fmt.Fprintf(stderr, "mcp-gate check: warning: %s\n", w)
	}
	_, _ = fmt.Fprintln(stdout, escrowLine(key, cfg.Escrow))
	if !*connect {
		return exitOK
	}
	logger := slog.New(slog.DiscardHandler)
	if *verbose {
		logger = slog.New(slog.NewTextHandler(stderr, nil))
	}
	return connectAll(ctx, cfg, names, oauth.NewStore(*stateDir), *timeout, logger, stdout)
}

// escrowLine says whether the escrow would be on, where its key hash comes from (never the hash)
// and where its API is served.
func escrowLine(key *escrow.Key, c config.Escrow) string {
	line := escrowKeyLine(key)
	switch {
	case key == nil && c.Socket != nil:
		line += "; escrow.socket is ignored"
	case key == nil || c.Socket == nil:
	case *c.TCP:
		line += "; served on the listener and the socket " + c.Socket.Path
	default:
		line += "; served on the socket " + c.Socket.Path + " only"
	}
	return line
}

func escrowKeyLine(key *escrow.Key) string {
	switch {
	case key == nil:
		return "escrow: off (no key hash in " + escrow.KeyHashKey + ", " + escrow.KeyHashFileKey + ", " +
			escrow.KeyHashEnv + " or " + escrow.LegacyKeyHashEnv + ")"
	case key.Source == escrow.LegacyKeyHashEnv:
		return "escrow: on, key hash from " + key.Source + " (deprecated: rename it " + escrow.KeyHashEnv + ")"
	case key.Deprecated:
		return "escrow: on, key hash from " + key.Source + " (" + escrow.LegacyKeyHashEnv + " is set too, and deprecated)"
	default:
		return "escrow: on, key hash from " + key.Source
	}
}

// connectAll connects to every enabled server at once and prints one line per server.
func connectAll(ctx context.Context, cfg *config.Config, names []string, store *oauth.Store, timeout time.Duration, logger *slog.Logger, stdout io.Writer) int {
	if err := procutil.SetNonDumpable(); err != nil {
		logger.Warn("cannot make the process non-dumpable", "error", err)
	}
	if r, err := procutil.EnableSubreaper(); err != nil {
		logger.Warn("cannot become a child subreaper", "error", err)
	} else {
		defer r.Close()
	}
	lines := make([]string, len(names))
	failed := false
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, name := range names {
		s := cfg.Servers[name]
		if s.Disabled {
			lines[i] = name + ": disabled"
			continue
		}
		wg.Go(func() {
			line, ok := connectOne(ctx, cfg, name, s, store, timeout, logger)
			mu.Lock()
			lines[i], failed = line, failed || !ok
			mu.Unlock()
		})
	}
	wg.Wait()
	for _, l := range lines {
		_, _ = fmt.Fprintln(stdout, l)
	}
	if failed {
		return exitTrouble
	}
	return exitOK
}

func connectOne(ctx context.Context, cfg *config.Config, name string, s *config.Server, store *oauth.Store, timeout time.Duration, logger *slog.Logger) (string, bool) {
	sup, err := downstream.New(gate.DownstreamOptions(cfg, name, s, childEnviron(parentEnviron(), cfg.Escrow.KeyHashVars...), version.Get().Version, store, logger))
	if err != nil {
		return fmt.Sprintf("%s: failed: %v", name, err), false
	}
	sup.Start(ctx)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = sup.Stop(stopCtx)
	}()
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err = sup.Wait(wctx, func(st downstream.Status) bool {
		return st.State == downstream.Ready || st.State == downstream.Backoff || st.AwaitsLogin()
	})
	st := sup.Status()
	if st.AwaitsLogin() {
		return fmt.Sprintf("%s: %s", name, st.LastError), false
	}
	if err != nil || st.State != downstream.Ready {
		reason := st.LastError
		if reason == "" {
			reason = "did not connect within " + timeout.String()
		}
		return fmt.Sprintf("%s: failed: %s", name, reason), false
	}
	tools := 0
	err = sup.Call(wctx, func(ctx context.Context, cs *mcp.ClientSession) error {
		if cs.InitializeResult().Capabilities == nil || cs.InitializeResult().Capabilities.Tools == nil {
			return nil
		}
		for _, err := range cs.Tools(ctx, nil) {
			if err != nil {
				return err
			}
			tools++
		}
		return nil
	})
	if err != nil {
		return fmt.Sprintf("%s: connected, but listing tools failed: %s", name, sup.ErrorText(err)), false
	}
	pin := ""
	if st.AutoPinned {
		pin = " (pinned automatically: the server did not answer the 2026-07-28 handshake)"
	}
	return fmt.Sprintf("%s: ready, protocol %s%s, %d tools", name, st.ProtocolVersion, pin, tools), true
}
