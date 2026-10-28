// Command mcp-gate is an MCP gateway: serve runs it; compare diffs the catalogs that MCP endpoints
// serve, check validates a config and can connect to its servers, import converts an mcp-proxy
// config, auth manages OAuth grants, toolpins shows and accepts pinned tool definitions, and
// approvals decides the tool calls a running gate holds.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/procutil"
	"github.com/vsem-azamat/mcp-gate/internal/version"
)

// Exit codes returned by run.
const (
	exitOK    = 0
	exitDrift = 1 // compare found differences
	exitUsage = 2
	// exitTrouble is a failure at run time; it shares 2 with usage errors, as diff(1) does.
	exitTrouble = 2
)

const usage = `Usage: mcp-gate <command>

Commands:
  serve      serve the servers of a config
  check      validate a config, and with -connect connect to its servers
  compare    compare the catalogs that MCP endpoints or snapshots serve
  import     convert an mcp-proxy config.json into an mcp-gate config
  auth       log in to, and out of, the servers that use OAuth
  toolpins   show and accept the tool definitions the gate pinned
  approvals  list, approve and deny the tool calls a running gate holds
  help       show this help
  version    print the version and commit
`

// lookupEnv reads an environment variable, like os.LookupEnv.
type lookupEnv func(string) (string, bool)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel() // the first signal begins the shutdown
		forceExit(<-sigs)
	}()
	code := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	signal.Stop(sigs)
	cancel()
	os.Exit(code)
}

// forceExit ends the process at a second signal, without waiting for the shutdown: it kills the
// process group of every child, so that their own children go too, and then dies of the signal.
func forceExit(sig os.Signal) {
	procutil.KillAll()
	signal.Reset(sig)
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(os.Getpid(), s)
	}
	// The signal is delivered asynchronously; give it the time to end the process.
	time.Sleep(time.Second)
	os.Exit(exitTrouble)
}

// run executes the command named by args and returns the process exit code.
func run(ctx context.Context, args []string, env lookupEnv, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "serve":
		return runServe(ctx, args[1:], env, stderr)
	case "check":
		return runCheck(ctx, args[1:], env, stdout, stderr)
	case "compare":
		return runCompare(ctx, args[1:], env, stdout, stderr)
	case "import":
		return runImport(args[1:], stdout, stderr)
	case "auth":
		return runAuth(ctx, args[1:], env, stdout, stderr)
	case "toolpins":
		return runToolpins(args[1:], env, stdout, stderr)
	case "approvals":
		return runApprovals(ctx, args[1:], env, stdout, stderr)
	case "help", "-h", "-help", "--help":
		_, _ = io.WriteString(stdout, usage)
		return exitOK
	case "version", "--version":
		_, _ = fmt.Fprintf(stdout, "mcp-gate %s\n", version.Get())
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "mcp-gate: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}
