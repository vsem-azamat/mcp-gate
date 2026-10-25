// Command mcp-gate is an MCP gateway: serve runs it; compare diffs the catalogs that MCP endpoints
// serve, check validates a config and can connect to its servers, and import converts an
// mcp-proxy config.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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
  help       show this help
  version    print the version and commit
`

// lookupEnv reads an environment variable, like os.LookupEnv.
type lookupEnv func(string) (string, bool)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
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
