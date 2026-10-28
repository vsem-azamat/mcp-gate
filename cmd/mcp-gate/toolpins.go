package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/toolpins"
)

const toolpinsUsage = `Usage: mcp-gate toolpins <command> [flags] [server] [tool...]

Shows and accepts the tool definitions the gate pins for servers with toolPins set to warn or
hold. The pins are kept in the toolpins directory under the state directory, which must be the
one mcp-gate serve uses; run these commands as the gate's user, who owns it. No config or network
is needed.

Commands:
  list [server]                     each server's accepted tools, and the tools it lists with
                                    another definition (changed) or without one accepted (added)
  diff <server> [tool...]           what differs between the accepted and the listed definition
                                    of the pending tools, field by field
  accept <server> <tool>=<hash>...  accept the listed definition of each tool, if its hash is
                                    still the one diff showed
  accept -all <server>              accept the listed definition of every pending tool

A reload of the gate (SIGHUP) serves what was accepted at once.

Exit status: 0 done (for diff, nothing pending), 1 diff shows a pending tool, 2 otherwise.
`

// acceptRE is the form of a tool to accept: its name and the hash of its pending definition.
var acceptRE = regexp.MustCompile(`^(.+)=(sha256:[0-9a-f]{64})$`)

func runToolpins(args []string, env lookupEnv, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, toolpinsUsage)
		return exitUsage
	}
	cmd := args[0]
	switch cmd {
	case "list", "diff", "accept":
	case "help", "-h", "-help", "--help":
		_, _ = io.WriteString(stdout, toolpinsUsage)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "mcp-gate toolpins: unknown command %q\n\n%s", cmd, toolpinsUsage)
		return exitUsage
	}
	fs := flag.NewFlagSet("toolpins "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), toolpinsUsage+"\nFlags:\n")
		fs.PrintDefaults()
	}
	stateDir := fs.String("state-dir", defaultStateDir(env), "the gate's state directory (default $STATE_DIRECTORY)")
	var all *bool
	if cmd == "accept" {
		all = fs.Bool("all", false, "accept every pending tool as it is listed now")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	prefix := "mcp-gate toolpins " + cmd
	rest := fs.Args()
	usage := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", prefix, fmt.Sprintf(format, a...))
		return exitUsage
	}
	switch {
	case cmd == "list" && len(rest) > 1:
		return usage("name at most one server")
	case cmd != "list" && len(rest) == 0:
		return usage("name the server")
	}
	if len(rest) > 0 && !config.ServerNameRE.MatchString(rest[0]) {
		return usage("%q is not a server name", rest[0])
	}
	var want map[string]string
	if cmd == "accept" {
		switch {
		case *all && len(rest) > 1:
			return usage("-all takes no tools")
		case !*all && len(rest) == 1:
			return usage("name the tools as <tool>=<hash>, as diff shows them, or pass -all")
		}
		want = map[string]string{}
		for _, arg := range rest[1:] {
			m := acceptRE.FindStringSubmatch(arg)
			if m == nil {
				return usage("%q is not <tool>=sha256:<hex>, as diff shows it", toolpins.Visible(arg))
			}
			want[m[1]] = m[2]
		}
	}
	if *stateDir == "" {
		return usage("no state directory: set -state-dir to the one mcp-gate serve uses")
	}
	if err := ownStateDir(*stateDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", prefix, err)
		return exitTrouble
	}
	store := toolpins.New(*stateDir)
	var err error
	code := exitOK
	switch cmd {
	case "list":
		err = toolpinsList(store, rest, stdout)
	case "diff":
		code, err = toolpinsDiff(store, rest[0], rest[1:], stdout)
	case "accept":
		err = toolpinsAccept(store, rest[0], want, stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", prefix, err)
		return exitTrouble
	}
	return code
}

// ownStateDir refuses a state directory, or a toolpins directory in it, that the user running
// the command does not own: the lock files it would create there would lock the gate out, which
// then holds every tool.
func ownStateDir(dir string) error {
	uid := os.Geteuid()
	for _, d := range []string{dir, filepath.Join(dir, toolpins.Dir)} {
		fi, err := os.Stat(d) //nolint:gosec // the state directory the user names, which is the command's input
		if errors.Is(err, os.ErrNotExist) && d != dir {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot read the state directory: %w", err)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != uid {
			return fmt.Errorf("%s belongs to user %d, not to user %d running this command; run it as the gate's user", d, st.Uid, uid)
		}
	}
	return nil
}

func toolpinsList(store *toolpins.Store, only []string, stdout io.Writer) error {
	servers := only
	if len(servers) == 0 {
		var err error
		if servers, err = store.Servers(); err != nil {
			return err
		}
		if len(servers) == 0 {
			_, _ = fmt.Fprintln(stdout, "No tool pins.")
			return nil
		}
	}
	for _, server := range servers {
		f, err := store.Load(server)
		if err != nil {
			return fmt.Errorf("%s: %w", server, err)
		}
		pending := slices.Sorted(slices.Values(f.Pending()))
		line := fmt.Sprintf("%s: %d accepted", server, f.Accepted())
		if len(pending) > 0 {
			line += fmt.Sprintf(", %d pending", len(pending))
		}
		_, _ = fmt.Fprintln(stdout, line)
		for _, name := range pending {
			e := f.Tools[name]
			_, _ = fmt.Fprintf(stdout, "  %s: %s, listed %s as %s\n", toolpins.Visible(name), e.Change(),
				e.Pending.At.Format(time.RFC3339), e.Pending.Hash)
		}
	}
	return nil
}

func toolpinsDiff(store *toolpins.Store, server string, tools []string, stdout io.Writer) (int, error) {
	f, err := store.Load(server)
	if err != nil {
		return exitTrouble, fmt.Errorf("%s: %w", server, err)
	}
	names := tools
	if len(names) == 0 {
		names = f.Pending()
	}
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	var missing []string
	for _, name := range names {
		if e := f.Tools[name]; e == nil || e.Pending == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return exitTrouble, fmt.Errorf("%s: nothing pending for %s", server, toolpins.Visible(strings.Join(missing, ", ")))
	}
	if len(names) == 0 {
		_, _ = fmt.Fprintf(stdout, "Nothing pending for %s.\n", server)
		return exitOK, nil
	}
	for i, name := range names {
		if i > 0 {
			_, _ = fmt.Fprintln(stdout)
		}
		e := f.Tools[name]
		_, _ = fmt.Fprintf(stdout, "%s: %s: %s\n", server, toolpins.Visible(name), e.Change())
		var old []byte
		if e.Accepted != nil {
			old = e.Accepted.Definition
		}
		if err := toolpins.WriteDiff(stdout, old, e.Pending.Definition); err != nil {
			return exitTrouble, fmt.Errorf("%s: %w", toolpins.Visible(name), err)
		}
		_, _ = fmt.Fprintf(stdout, "  accept: %s=%s\n", toolpins.Visible(name), e.Pending.Hash)
	}
	return exitDrift, nil
}

func toolpinsAccept(store *toolpins.Store, server string, want map[string]string, stdout io.Writer) error {
	accepted, err := store.Accept(server, want)
	if err != nil {
		return fmt.Errorf("%s: %w", server, err)
	}
	if len(accepted) == 0 {
		_, _ = fmt.Fprintf(stdout, "Nothing pending for %s.\n", server)
		return nil
	}
	shown := make([]string, len(accepted))
	for i, name := range accepted {
		shown[i] = toolpins.Visible(name)
	}
	_, _ = fmt.Fprintf(stdout, "Accepted for %s: %s.\n"+
		"Reload the gate (SIGHUP, such as systemctl reload mcp-gate) to serve them now; otherwise\n"+
		"the gate serves them at the server's next listing.\n", server, strings.Join(shown, ", "))
	return nil
}
