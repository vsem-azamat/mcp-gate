package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/config"
	"github.com/vsem-azamat/mcp-gate/internal/oauth"
)

const authUsage = `Usage: mcp-gate auth <command> [-state-dir DIR] <config.yaml> [server]

Manages the OAuth grants of the HTTP servers that have an oauth block. The grants are kept in
the oauth directory under the state directory, which must be the one mcp-gate serve uses; run
these commands as the gate's user, with its environment. A running gate notices a new grant
at its next connect attempt and a deleted one at its next request.

Commands:
  login <config.yaml> <server>   sign in: prints a URL to open in any browser, then reads the
                                 address the browser is sent back to
  status <config.yaml>           show the grant of every OAuth server, without the network
  logout <config.yaml> <server>  revoke and delete a server's grant

Exit status: 0 done (for status, every enabled OAuth server has a grant), 2 otherwise.
`

// stdin is where auth login reads the pasted address.
var stdin io.Reader = os.Stdin

// loginTimeout bounds a login, most of which is the user signing in.
const loginTimeout = 15 * time.Minute

// defaultStateDir is the first directory of $STATE_DIRECTORY, which systemd sets for a unit
// with StateDirectory=.
func defaultStateDir(env lookupEnv) string {
	v, _ := env("STATE_DIRECTORY")
	v, _, _ = strings.Cut(v, ":")
	return v
}

func runAuth(ctx context.Context, args []string, env lookupEnv, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, authUsage)
		return exitUsage
	}
	cmd, want := args[0], 2
	switch cmd {
	case "login", "logout":
	case "status":
		want = 1
	case "help", "-h", "-help", "--help":
		_, _ = io.WriteString(stdout, authUsage)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "mcp-gate auth: unknown command %q\n\n%s", cmd, authUsage)
		return exitUsage
	}
	fs := flag.NewFlagSet("auth "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), authUsage+"\nFlags:\n")
		fs.PrintDefaults()
	}
	stateDir := fs.String("state-dir", defaultStateDir(env), "the gate's state directory (default $STATE_DIRECTORY)")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	prefix := "mcp-gate auth " + cmd
	if fs.NArg() != want {
		if want == 1 {
			_, _ = fmt.Fprintf(stderr, "%s: name the config file\n", prefix)
		} else {
			_, _ = fmt.Fprintf(stderr, "%s: name the config file and the server\n", prefix)
		}
		return exitUsage
	}
	if *stateDir == "" {
		_, _ = fmt.Fprintf(stderr, "%s: no state directory: set -state-dir to the one mcp-gate serve uses\n", prefix)
		return exitUsage
	}
	cfg, err := config.Load(fs.Arg(0), config.LookupFunc(env))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %s:\n  %s\n", prefix, fs.Arg(0), strings.ReplaceAll(err.Error(), "\n", "\n  "))
		return exitUsage
	}
	store := oauth.NewStore(*stateDir)
	if cmd == "status" {
		return authStatus(cfg, store, stdout)
	}
	name := fs.Arg(1)
	s := cfg.Servers[name]
	if s == nil || s.HTTP == nil || s.HTTP.OAuth == nil {
		_, _ = fmt.Fprintf(stderr, "%s: the config has no HTTP server %q with an oauth block\n", prefix, name)
		return exitUsage
	}
	if cmd == "logout" {
		return authLogout(ctx, store, name, s, stdout, stderr)
	}
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	if err := authLogin(ctx, cfg, name, s, store, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", prefix, err)
		return exitTrouble
	}
	return exitOK
}

func authLogin(ctx context.Context, cfg *config.Config, name string, s *config.Server, store *oauth.Store, stdout io.Writer) error {
	prev, err := store.Load(name)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "The kept grant cannot be read (%v); it is replaced.\n", err)
		prev = nil
	}
	hc := oauth.NewHTTPClient(s.HTTP.URL)
	p, err := oauth.BeginLogin(ctx, oauth.LoginOptions{
		Name: name, ServerURL: s.HTTP.URL, Config: *s.HTTP.OAuth, ClientName: cfg.Name + " (" + name + ")",
		Previous: prev, HTTPClient: hc,
	})
	if err != nil {
		return err
	}
	if p.Registered {
		_, _ = fmt.Fprintln(stdout, "Registered an OAuth client with the authorization server.")
	}
	_, _ = fmt.Fprintf(stdout, "Open this URL in a browser and sign in:\n\n  %s\n\n"+
		"The browser is then sent to %s?code=..., a page that does not load.\n"+
		"Copy that whole address from the address bar and paste it here.\n\nAddress: ",
		p.AuthURL, strings.SplitN(s.HTTP.OAuth.RedirectURL, "?", 2)[0])
	pasted, err := readLine(ctx, stdin)
	if err != nil {
		return err
	}
	g, err := p.Complete(ctx, pasted)
	if err != nil {
		return err
	}
	unlock, err := store.Lock(ctx, name)
	if err != nil {
		return err
	}
	defer unlock()
	if err := store.Save(name, g); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "\nLogged in to %s: %s.\n", name, describeTokens(g, time.Now()))
	if g.RefreshToken == "" {
		_, _ = fmt.Fprintln(stdout, "No refresh token was issued: log in again when the access token expires.")
	}
	return nil
}

// readLine reads one line, giving up when ctx ends.
func readLine(ctx context.Context, r io.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 4096), 64<<10)
		if sc.Scan() {
			ch <- result{line: sc.Text()}
			return
		}
		err := sc.Err()
		if err == nil {
			err = errors.New("nothing was pasted")
		}
		ch <- result{err: err}
	}()
	select {
	case res := <-ch:
		return res.line, res.err
	case <-ctx.Done():
		return "", fmt.Errorf("gave up waiting for the address: %w", ctx.Err())
	}
}

func describeTokens(g *oauth.Grant, now time.Time) string {
	var access string
	switch {
	case g.Expiry.IsZero():
		access = "access token without a stated expiry"
	case now.Before(g.Expiry):
		access = "access token valid for " + g.Expiry.Sub(now).Round(time.Minute).String()
	default:
		access = "access token expired"
	}
	if g.RefreshToken != "" {
		return access + ", with a refresh token"
	}
	return access + ", no refresh token"
}

func authStatus(cfg *config.Config, store *oauth.Store, stdout io.Writer) int {
	names := make([]string, 0, len(cfg.Servers))
	for name, s := range cfg.Servers {
		if s.HTTP != nil && s.HTTP.OAuth != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		_, _ = fmt.Fprintln(stdout, "No server uses OAuth.")
		return exitOK
	}
	now := time.Now()
	code := exitOK
	for _, name := range names {
		s := cfg.Servers[name]
		line, ok := grantLine(store, name, s, now)
		if s.Disabled {
			line += " (disabled)"
		} else if !ok {
			code = exitTrouble
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", name, line)
	}
	return code
}

// grantLine describes a server's grant and reports whether it can be used.
func grantLine(store *oauth.Store, name string, s *config.Server, now time.Time) (string, bool) {
	g, err := store.Load(name)
	switch {
	case err != nil:
		return "needs login: " + err.Error(), false
	case g == nil:
		return "needs login: not logged in", false
	}
	if why := g.Mismatch(s.HTTP.URL, s.HTTP.OAuth.ClientID); why != "" {
		return "needs login: " + why, false
	}
	client := "configured client"
	if g.Registered {
		client = "registered client"
	}
	usable := g.RefreshToken != "" || g.Expiry.IsZero() || now.Before(g.Expiry)
	state := "logged in"
	if !usable {
		state = "needs login"
	}
	return fmt.Sprintf("%s (%s, since %s): %s", state, client, g.ObtainedAt.UTC().Format(time.RFC3339), describeTokens(g, now)), usable
}

// authLogout revokes a server's grant at its authorization server, when that offers a
// revocation endpoint, and deletes it. A grant that cannot be revoked is deleted all the same.
func authLogout(ctx context.Context, store *oauth.Store, name string, s *config.Server, stdout, stderr io.Writer) int {
	unlock, err := store.Lock(ctx, name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gate auth logout: %v\n", err)
		return exitTrouble
	}
	defer unlock()
	revoked := "The authorization server offers no revocation endpoint, so it keeps the grant until it expires; revoke it there to end it sooner."
	g, err := store.Load(name)
	switch {
	case err != nil:
		revoked = "The grant could not be read, so it was not revoked; revoke it at the authorization server to end it sooner."
		_, _ = fmt.Fprintf(stderr, "mcp-gate auth logout: %v\n", err)
	case g != nil:
		has, err := oauth.Revoke(ctx, oauth.RevokeOptions{Grant: g, Config: *s.HTTP.OAuth, HTTPClient: oauth.NewHTTPClient(s.HTTP.URL)})
		switch {
		case err != nil:
			revoked = "Revoking it at the authorization server failed; revoke it there to end it sooner."
			_, _ = fmt.Fprintf(stderr, "mcp-gate auth logout: %v\n", err)
		case has:
			revoked = "The authorization server revoked it."
		}
	}
	ok, err := store.Delete(name)
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "mcp-gate auth logout: %v\n", err)
		return exitTrouble
	case !ok:
		_, _ = fmt.Fprintf(stdout, "%s was not logged in.\n", name)
	default:
		_, _ = fmt.Fprintf(stdout, "Logged out of %s: its grant is deleted. %s\n", name, revoked)
	}
	return exitOK
}
