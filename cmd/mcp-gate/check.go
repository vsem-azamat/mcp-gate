package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

const checkUsage = `Usage: mcp-gate check [flags] <config.yaml>

Loads and validates an mcp-gate config: strict YAML, ${VAR} expanded from the environment.

Exit status: 0 valid, 2 otherwise.

Flags:
`

func runCheck(args []string, env lookupEnv, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), checkUsage)
		fs.PrintDefaults()
	}
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
	cfg, err := config.Load(fs.Arg(0), config.LookupFunc(env))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate check: %s:\n  %s\n", fs.Arg(0), strings.ReplaceAll(err.Error(), "\n", "\n  "))
		return exitUsage
	}
	disabled := 0
	for _, s := range cfg.Servers {
		if s.Disabled {
			disabled++
		}
	}
	_, _ = fmt.Fprintf(stdout, "%s: valid, %d servers (%d disabled)\n", fs.Arg(0), len(cfg.Servers), disabled)
	return exitOK
}
