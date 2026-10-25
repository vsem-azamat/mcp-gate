// Command mcp-gate is an MCP gateway. Only the command-line skeleton exists so far.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes returned by run.
const (
	exitOK    = 0
	exitUsage = 2
)

const usage = `Usage: mcp-gate <command>

Commands:
  help    show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command named by args and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		_, _ = io.WriteString(stdout, usage)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "mcp-gate: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}
