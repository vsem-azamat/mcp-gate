package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/escrow"
	"github.com/vsem-azamat/mcp-gate/internal/gate"
	"github.com/vsem-azamat/mcp-gate/internal/procutil"
	"github.com/vsem-azamat/mcp-gate/internal/systemd"
	"github.com/vsem-azamat/mcp-gate/internal/version"
)

const serveUsage = `Usage: mcp-gate serve [flags] <config.yaml>

Serves the servers of an mcp-gate config: each at /<name>/mcp on listen.addr, behind its tokens,
with /_healthz, /_readyz and, with admin tokens, /_status. With the hex SHA-256 of an API key in
escrow.keyHash, escrow.keyHashFile or MCP_GATE_ESCROW_KEY_SHA256, redacted secrets are kept in
memory and served at /_escrow/ to that key. Logs are JSON lines on stderr. SIGINT and SIGTERM
shut it down; SIGHUP reloads the config file. Under systemd it serves the socket a socket unit
passes (LISTEN_FDS) in place of listen.addr, and reports readiness on NOTIFY_SOCKET.

Exit status: 0 after a clean shutdown, 2 when the config is invalid or the gate fails.

Flags:
`

// childEnviron drops the escrow key hash variables, the variables named in extra (those
// escrow.keyHash was expanded from) and systemd's socket activation and notification variables
// from the environment stdio children inherit from, so that no inheritEnv pattern hands them to
// a child.
func childEnviron(environ []string, extra ...string) []string {
	names := slices.Concat([]string{escrow.KeyHashEnv, escrow.LegacyKeyHashEnv}, systemd.Vars, extra)
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
	levelVar := new(slog.LevelVar)
	levelVar.Set(level)
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: levelVar}))
	// Taken from the start: SIGHUP would otherwise end the process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
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
	notifier, err := systemd.NewNotifier(env)
	if err != nil {
		logger.Warn("not notifying systemd", "error", err.Error())
	}
	notify := func(state string) {
		if err := notifier.Notify(state); err != nil {
			logger.Warn("cannot notify systemd", "error", err.Error())
		}
	}
	g, err := gate.New(gate.Options{
		Config: cfg, Environ: childEnviron(parentEnviron(), cfg.Escrow.KeyHashVars...), StateDir: *stateDir, Version: version.Get().Version, Logger: logger,
		EscrowKey: key, Notify: notify, Level: levelVar,
	})
	if err != nil {
		logger.Error("cannot start", "error", err.Error())
		return exitTrouble
	}
	ln, err := listen(ctx, g, cfg, env, logger)
	if err != nil {
		logger.Error("cannot listen", "error", err.Error())
		return exitTrouble
	}
	reloads, stopReloads := context.WithCancel(ctx)
	reloaded := make(chan struct{})
	go func() {
		defer close(reloaded)
		for {
			select {
			case <-reloads.Done():
				return
			case <-hup:
				reload(reloads, g, fs.Arg(0), env, logger)
			}
		}
	}()
	err = g.Run(ctx, ln)
	stopReloads()
	<-reloaded
	if err != nil {
		logger.Error("gate failed", "error", err.Error())
		return exitTrouble
	}
	logger.Info("stopped")
	return exitOK
}

// reload loads the config file again and applies it. A config that does not load, or that the
// gate cannot apply, is logged and the running one stays.
func reload(ctx context.Context, g *gate.Gate, path string, env lookupEnv, logger *slog.Logger) {
	var called, loaded bool
	err := g.Reload(ctx, func() (*config.Config, error) {
		called = true
		logger.Info("reloading the config", "path", path)
		cfg, err := config.Load(path, config.LookupFunc(env))
		loaded = err == nil
		return cfg, err
	})
	switch {
	case err == nil:
	case !called:
		logger.Warn("not reloading the config", "reason", err.Error())
	case !loaded:
		logger.Error("the config does not load; keeping the running one", "error", err.Error())
	default:
		logger.Error("cannot apply the config; keeping the running one", "error", err.Error())
	}
}

// listen returns the listening socket systemd passed, or else opens listen.addr. A passed socket
// is served whatever its address; one that is not on listen.addr is logged.
func listen(ctx context.Context, g *gate.Gate, cfg *config.Config, env lookupEnv, logger *slog.Logger) (net.Listener, error) {
	ln, err := systemd.Listener(env, os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("the socket systemd passed: %w", err)
	}
	if ln == nil {
		ln, err := g.Listen(ctx)
		if err != nil {
			return nil, fmt.Errorf("listen.addr %s: %w", cfg.Listen.Addr, err)
		}
		return ln, nil
	}
	logger.Info("serving the socket systemd passed", "addr", ln.Addr().String())
	if !sameAddr(ln.Addr(), cfg.Listen.Addr) {
		logger.Warn("the socket systemd passed is not on listen.addr; the socket unit's ListenStream= wins",
			"socket", ln.Addr().String(), "listenAddr", cfg.Listen.Addr)
	}
	return ln, nil
}

// sameAddr reports whether a listener's address is the configured one: the same port, and the
// same IP, an unspecified address (or an empty host) matching only another, and localhost
// matching only a loopback address. Any other host name is taken not to match, since the gate
// cannot tell what it resolves to.
func sameAddr(a net.Addr, configured string) bool {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	host, port, err := net.SplitHostPort(configured)
	if err != nil || port != strconv.Itoa(tcp.Port) {
		return false
	}
	got, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	got = got.Unmap()
	switch {
	case host == "":
		return got.IsUnspecified()
	case strings.EqualFold(host, "localhost"):
		return got.IsLoopback()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return got == ip || (got.IsUnspecified() && ip.IsUnspecified())
}
