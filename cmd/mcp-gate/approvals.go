package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/approval"
	"github.com/vsem-azamat/mcp-gate/internal/config"
)

const approvalsUsage = `Usage: mcp-gate approvals [-url URL] <command>

Lists and decides the tool calls that a running gate holds for the owner's approval, through
its /_approvals endpoint. The admin token is read from MCP_GATE_ADMIN_TOKEN, never from an
argument.

Commands:
  list           show the pending approvals, oldest first, with their arguments (redacted)
  approve <id>   let the call go to its server
  deny <id>      answer the call with an error, without forwarding it

Exit status: 0 done, 2 otherwise (an unknown or already decided id included).

Flags:
`

// approvalsTimeout bounds one request to the gate.
const approvalsTimeout = 15 * time.Second

// approvalsClient is the HTTP client of the command; a variable for tests.
var approvalsClient = &http.Client{Timeout: approvalsTimeout}

func runApprovals(ctx context.Context, args []string, env lookupEnv, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), approvalsUsage)
		fs.PrintDefaults()
	}
	defaultURL, _ := env("MCP_GATE_URL")
	if defaultURL == "" {
		defaultURL = "http://" + config.DefaultListenAddr
	}
	base := fs.String("url", defaultURL, "the gate's base URL (default $MCP_GATE_URL, else http://"+config.DefaultListenAddr+")")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "mcp-gate approvals: "+format+"\n", a...)
		return exitTrouble
	}
	rest := fs.Args()
	var method, path string
	switch {
	case len(rest) == 1 && rest[0] == "list":
		method, path = http.MethodGet, approval.Route
	case len(rest) == 2 && (rest[0] == "approve" || rest[0] == "deny"):
		method, path = http.MethodPost, approval.Route+"/"+url.PathEscape(rest[1])+"/"+rest[0]
	default:
		fs.Usage()
		return exitUsage
	}
	token, _ := env("MCP_GATE_ADMIN_TOKEN")
	if strings.TrimSpace(token) == "" {
		return fail("set MCP_GATE_ADMIN_TOKEN to one of the gate's admin.tokens")
	}
	ctx, cancel := context.WithTimeout(ctx, approvalsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(*base, "/")+path, nil)
	if err != nil {
		return fail("-url is not a valid URL")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	res, err := approvalsClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fail("cannot reach the gate at %s: %v", *base, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return fail("reading the answer: %v", err)
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return fail("the gate did not accept MCP_GATE_ADMIN_TOKEN")
	case http.StatusNotFound:
		if method == http.MethodPost {
			return fail("no pending approval %s: it was decided, it expired, or the id is wrong", rest[1])
		}
		return fail("the gate serves no /_approvals: it needs admin.tokens")
	default:
		return fail("the gate answered %d", res.StatusCode)
	}
	if method == http.MethodPost {
		var d struct {
			ID       string `json:"id"`
			Approval string `json:"approval"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			return fail("cannot read the answer: %v", err)
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", d.ID, d.Approval)
		return exitOK
	}
	var list struct {
		Pending []approval.Pending `json:"pending"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return fail("cannot read the answer: %v", err)
	}
	if len(list.Pending) == 0 {
		_, _ = fmt.Fprintln(stdout, "no pending approvals")
		return exitOK
	}
	now := time.Now()
	for _, p := range list.Pending {
		by := p.Principal
		if by == "" {
			by = "(no token)"
		}
		left := max(p.Expires.Sub(now), 0).Truncate(time.Second)
		_, _ = fmt.Fprintf(stdout, "%s  %s/%s  by %s  %s left\n", p.ID, p.Server, p.Tool, by, left)
		if p.Arguments != "" {
			_, _ = fmt.Fprintf(stdout, "  %s\n", p.Arguments)
		}
	}
	return exitOK
}
