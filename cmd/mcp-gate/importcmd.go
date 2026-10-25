package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/vsem-azamat/mcp-gate/internal/config/importer"
)

const importUsage = `Usage: mcp-gate import [-partial] <config.json>

Converts an mcp-proxy config.json into an mcp-gate config and writes it to stdout. Keys this
build does not implement make the import fail, listing them; with -partial the config is
written anyway, each dropped key marked "NOT IMPLEMENTED IN THIS BUILD", and mcp-gate check
rejects it until those marks are removed. Notes go to stderr; none quotes a value.

Exit status: 0 written, 2 otherwise.

Flags:
`

func runImport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), importUsage)
		fs.PrintDefaults()
	}
	partial := fs.Bool("partial", false, "write the config even when keys are not implemented, marking them")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "mcp-gate import: name one mcp-proxy config file")
		return exitUsage
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate import: %v\n", err)
		return exitUsage
	}
	res, err := importer.Import(data, importer.Options{Partial: *partial})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate import: %v\n", err)
		return exitUsage
	}
	for _, w := range res.Warnings {
		_, _ = fmt.Fprintf(stderr, "mcp-gate import: note: %s\n", w)
	}
	for _, k := range res.Unimplemented {
		_, _ = fmt.Fprintf(stderr, "mcp-gate import: dropped, not implemented: %s\n", k)
	}
	if _, err := stdout.Write(res.YAML); err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate import: %v\n", err)
		return exitTrouble
	}
	return exitOK
}
