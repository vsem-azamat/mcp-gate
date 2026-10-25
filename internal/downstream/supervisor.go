// Package downstream connects mcp-gate to one downstream MCP server and keeps it connected.
//
// A Supervisor owns the server's connection: for stdio it starts the child process, in a process
// group of its own, and speaks to it over a line-framed connection of the gate's own; for HTTP
// it uses the SDK's streamable client with a size-limited HTTP client. It probes the server,
// restarts it with backoff after a failure, never while calls are in flight, and pins the
// protocol version to 2025-11-25 when the server does not answer the 2026-07-28 handshake.
package downstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/procutil"
	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// Protocol versions the supervisor treats specially.
const (
	// StatelessVersion is the first protocol version negotiated by server/discover.
	StatelessVersion = "2026-07-28"
	// AutoPinVersion is the version pinned when a server ignores server/discover.
	AutoPinVersion = "2025-11-25"
)

// Defaults for Options fields left at zero.
const (
	DefaultMaxMessageBytes = 16 << 20
	DefaultProbeInterval   = 30 * time.Second
	DefaultMaxBackoff      = 30 * time.Second
	DefaultDiscoverTimeout = 5 * time.Second
	DefaultConnectTimeout  = 60 * time.Second
	DefaultProbeTimeout    = 10 * time.Second
	DefaultStopGrace       = 5 * time.Second
	DefaultInitialBackoff  = time.Second
	DefaultStableAfter     = time.Minute
	DefaultProbeFailures   = 3
	maxErrorLen            = 512
)

// Stdio describes a server started as a child process.
type Stdio struct {
	Command string
	Args    []string
	Dir     string
	// Env is set in the child's environment and wins over inherited values.
	Env map[string]string
	// InheritEnv names the variables of ParentEnv the child gets; a trailing * matches a prefix.
	InheritEnv []string
	// ParentEnv is the gate's environment, in os.Environ form.
	ParentEnv []string
}

// HTTP describes a server reached over streamable HTTP.
type HTTP struct {
	URL     string
	Headers map[string]string
}

// Options configure a Supervisor. Exactly one of Stdio and HTTP is set.
type Options struct {
	Name  string
	Stdio *Stdio
	HTTP  *HTTP
	// Disabled leaves the server stopped, in state Disabled.
	Disabled bool

	// ClientName and ClientVersion are sent to the server as clientInfo.
	ClientName, ClientVersion string
	// CallTimeout bounds each Call; 0 means no bound.
	CallTimeout time.Duration
	// MaxMessageBytes caps one stdio frame, one HTTP response body or one event.
	MaxMessageBytes int
	// ProtocolVersion, if set, is offered to the server instead of the latest version.
	ProtocolVersion string
	// LearnedPin is an automatic pin learned earlier (see OnPinLearned).
	LearnedPin string
	// OnPinLearned, if set, is called when the supervisor pins AutoPinVersion because the server
	// did not answer the 2026-07-28 handshake, so the pin can be stored.
	OnPinLearned  func(version string)
	ProbeInterval time.Duration
	MaxBackoff    time.Duration

	Logger *slog.Logger
	// Redactor scrubs child stderr lines and error messages; nil uses the default rules.
	Redactor *redact.Engine

	// Tuning, mostly for tests; zero means the default.
	DiscoverTimeout time.Duration // the sub-deadline for a connect without a pin
	ConnectTimeout  time.Duration
	ProbeTimeout    time.Duration
	StopGrace       time.Duration // between SIGTERM and SIGKILL
	InitialBackoff  time.Duration
	StableAfter     time.Duration // a session that lived this long resets the backoff
	ProbeFailures   int           // consecutive failed probes before a restart
}

func (o *Options) applyDefaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if o.MaxMessageBytes <= 0 {
		o.MaxMessageBytes = DefaultMaxMessageBytes
	}
	def(&o.ProbeInterval, DefaultProbeInterval)
	def(&o.MaxBackoff, DefaultMaxBackoff)
	def(&o.DiscoverTimeout, DefaultDiscoverTimeout)
	def(&o.ConnectTimeout, DefaultConnectTimeout)
	def(&o.ProbeTimeout, DefaultProbeTimeout)
	def(&o.StopGrace, DefaultStopGrace)
	def(&o.InitialBackoff, DefaultInitialBackoff)
	def(&o.StableAfter, DefaultStableAfter)
	if o.ProbeFailures <= 0 {
		o.ProbeFailures = DefaultProbeFailures
	}
	if o.ClientName == "" {
		o.ClientName = "mcp-gate"
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
}

// State is the state of a supervised server.
type State int

// The states of a supervised server.
const (
	Starting State = iota // connecting, for the first time or after a restart
	Ready                 // connected and answering
	Degraded              // connected, but the last probe failed; calls still go through
	Backoff               // waiting before the next restart
	Disabled              // disabled in the config
	Stopped               // stopped by Stop
)

func (s State) String() string {
	switch s {
	case Starting:
		return "starting"
	case Ready:
		return "ready"
	case Degraded:
		return "degraded"
	case Backoff:
		return "backoff"
	case Disabled:
		return "disabled"
	case Stopped:
		return "stopped"
	default:
		return fmt.Sprintf("State(%d)", int(s))
	}
}

// Status is a snapshot of a supervised server.
type Status struct {
	State State
	// ProtocolVersion is the version negotiated by the current session.
	ProtocolVersion string
	// AutoPinned reports that the session runs on the automatic pin.
	AutoPinned bool
	// Restarts counts the connection attempts after the first.
	Restarts    int
	LastError   string // redacted
	LastErrorAt time.Time
	// PID is the child's process ID, for a stdio server with a running child.
	PID int
	// Stderr is the most recent stderr output of the child, redacted.
	Stderr []string
}

// NotReadyError is returned by Call when the server has no usable session.
type NotReadyError struct {
	Name  string
	State State
}

func (e *NotReadyError) Error() string {
	return fmt.Sprintf("server %s is not ready (%s)", e.Name, e.State)
}

// Supervisor keeps one downstream server connected.
type Supervisor struct {
	opts     Options
	logger   *slog.Logger
	redactor *redact.Engine
	client   *mcp.Client
	stderr   *procutil.LineLog
	http     *http.Client
	httpBase *http.Transport

	mu         sync.Mutex
	state      State
	session    *mcp.ClientSession
	version    string
	learned    string
	autoPinned bool
	restarts   int
	lastErr    string
	lastErrAt  time.Time
	pid        int
	inflight   int
	calls      uint64 // calls started, to tell whether one overlapped a probe
	changed    chan struct{}

	stop      chan struct{}
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// New returns a supervisor for the server described by opts. Start starts it.
func New(opts Options) (*Supervisor, error) {
	if (opts.Stdio == nil) == (opts.HTTP == nil) {
		return nil, errors.New("downstream: exactly one of Stdio and HTTP must be set")
	}
	opts.applyDefaults()
	r := opts.Redactor
	if r == nil {
		var err error
		if r, err = redact.New(redact.Options{}); err != nil {
			return nil, err
		}
	}
	logger := opts.Logger.With("server", opts.Name)
	s := &Supervisor{
		opts: opts, logger: logger, redactor: r, learned: opts.LearnedPin,
		changed: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{}),
	}
	s.client = mcp.NewClient(&mcp.Implementation{Name: opts.ClientName, Version: opts.ClientVersion}, &mcp.ClientOptions{
		Logger:         logger,
		Capabilities:   &mcp.ClientCapabilities{},
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	if opts.Stdio != nil {
		s.stderr = procutil.NewLineLog(logger, s.scrub, 0)
	} else {
		s.http, s.httpBase = newHTTPClient(opts.HTTP.Headers, opts.MaxMessageBytes, logger)
	}
	if opts.Disabled {
		s.state = Disabled
	}
	return s, nil
}

func (s *Supervisor) scrub(text string) string { return s.redactor.RedactText(text, redact.Marker{}) }

// ErrorText returns err's message fit for logs and status: the server's URL, which may carry a
// credential in its path or query, is replaced by its config path, the redaction rules run, and
// the text is cut at 512 bytes.
func (s *Supervisor) ErrorText(err error) string {
	msg := err.Error()
	if h := s.opts.HTTP; h != nil && h.URL != "" {
		placeholder := "<servers." + s.opts.Name + ".http.url>"
		forms := []string{h.URL, strings.Trim(strconv.Quote(h.URL), `"`)}
		if u, perr := url.Parse(h.URL); perr == nil {
			forms = append(forms, u.String(), u.Redacted())
		}
		for _, f := range forms {
			msg = strings.ReplaceAll(msg, f, placeholder)
		}
	}
	msg = s.scrub(msg)
	if len(msg) > maxErrorLen {
		msg = msg[:maxErrorLen] + "…"
	}
	return msg
}

// Start starts supervising in the background. The values of ctx, not its cancellation, carry
// into the supervisor's requests; Stop ends it. Start does nothing for a disabled server.
func (s *Supervisor) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		if s.opts.Disabled {
			close(s.done)
			return
		}
		go s.run(context.WithoutCancel(ctx))
	})
}

// Stop stops the server, ending its child's process group, and waits until that is done or ctx
// is done. In-flight calls fail.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
	s.startOnce.Do(func() { close(s.done) }) // never started
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.httpBase != nil {
		s.httpBase.CloseIdleConnections()
	}
	if !s.opts.Disabled {
		s.setState(Stopped)
	}
	return nil
}

// Status returns a snapshot of the server's state.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	st := Status{
		State: s.state, ProtocolVersion: s.version, Restarts: s.restarts,
		LastError: s.lastErr, LastErrorAt: s.lastErrAt, PID: s.pid,
		AutoPinned: s.autoPinned,
	}
	s.mu.Unlock()
	if s.stderr != nil {
		st.Stderr = s.stderr.Tail()
	}
	return st
}

// Wait blocks until cond holds for the server's status or ctx is done.
func (s *Supervisor) Wait(ctx context.Context, cond func(Status) bool) error {
	for {
		s.mu.Lock()
		ch := s.changed
		s.mu.Unlock()
		if cond(s.Status()) {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Call runs fn with the current session, bounded by the call timeout. While it runs, no probe
// is sent and no restart begins. It fails with a *NotReadyError when there is no session.
func (s *Supervisor) Call(ctx context.Context, fn func(context.Context, *mcp.ClientSession) error) error {
	s.mu.Lock()
	cs, state := s.session, s.state
	if cs == nil || (state != Ready && state != Degraded) {
		s.mu.Unlock()
		return &NotReadyError{Name: s.opts.Name, State: state}
	}
	s.inflight++
	s.calls++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	if s.opts.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.CallTimeout)
		defer cancel()
	}
	return fn(ctx, cs)
}

// setState records a state and wakes Wait.
func (s *Supervisor) setState(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setStateLocked(st)
}

func (s *Supervisor) setStateLocked(st State) {
	if s.state == st {
		return
	}
	s.logger.Info("server state", "from", s.state.String(), "to", st.String())
	s.state = st
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Supervisor) recordError(err error) {
	msg := s.ErrorText(err)
	s.mu.Lock()
	s.lastErr, s.lastErrAt = msg, time.Now()
	s.mu.Unlock()
	s.logger.Warn("server failed", "error", msg)
}

func (s *Supervisor) stopping() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// run is the supervision loop: connect, serve until the session ends, restart after a backoff.
func (s *Supervisor) run(base context.Context) {
	defer close(s.done)
	backoff := s.opts.InitialBackoff
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			s.mu.Lock()
			s.restarts++
			s.mu.Unlock()
		}
		s.setState(Starting)
		a, err := s.connect(base)
		if err == nil {
			s.mu.Lock()
			s.autoPinned = a.autoPinned
			s.mu.Unlock()
			began := time.Now()
			err = s.serve(base, a)
			if !s.stopping() {
				s.recordError(err)
			}
			s.mu.Lock()
			s.session, s.version, s.pid, s.autoPinned = nil, "", 0, false
			if !s.stopping() {
				// The restart begins: no call starts on the session being closed, and Backoff
				// waits until the old child is gone.
				s.setStateLocked(Starting)
			}
			s.mu.Unlock()
			a.close(s.opts.StopGrace, s.logger)
			if time.Since(began) >= s.opts.StableAfter {
				backoff = s.opts.InitialBackoff
			}
		} else if !s.stopping() {
			s.recordError(err)
		}
		if s.stopping() {
			return
		}
		s.setState(Backoff)
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-s.stop:
			t.Stop()
			return
		}
		backoff = min(backoff*2, s.opts.MaxBackoff)
	}
}

// attempt is one connection to the server.
type attempt struct {
	session    *mcp.ClientSession
	autoPinned bool              // the session runs on the automatic pin
	sessDone   chan struct{}     // closed when the session has ended
	sessErr    error             // why, once sessDone is closed
	proc       *procutil.Process // stdio only
}

func (a *attempt) close(grace time.Duration, logger *slog.Logger) {
	_ = a.session.Close()
	<-a.sessDone
	if a.proc != nil {
		if err := a.proc.Stop(grace); err != nil {
			logger.Error("child process group did not exit", "error", err)
		}
	}
}

// connect opens a session. Without a pin, the attempt gets DiscoverTimeout: a server that does
// not answer in that time is torn down and reconnected pinned to AutoPinVersion.
func (s *Supervisor) connect(base context.Context) (*attempt, error) {
	ctx, cancel := context.WithTimeout(base, s.opts.ConnectTimeout)
	defer cancel()
	go func() { // Stop interrupts a connect
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	pin := s.opts.ProtocolVersion
	if pin == "" {
		pin = s.learned
	}
	if pin != "" {
		a, err := s.dial(ctx, pin)
		if a != nil {
			a.autoPinned = s.opts.ProtocolVersion == ""
		}
		return a, err
	}
	sub, cancelSub := context.WithTimeout(ctx, s.opts.DiscoverTimeout)
	a, err := s.dial(sub, "")
	subExpired := errors.Is(sub.Err(), context.DeadlineExceeded)
	cancelSub()
	if err == nil || !subExpired || ctx.Err() != nil {
		return a, err
	}
	s.logger.Warn("the server did not complete the handshake in time; retrying with a pinned protocol version",
		"version", AutoPinVersion, "timeout", s.opts.DiscoverTimeout.String())
	began := time.Now()
	if a, err = s.dial(ctx, AutoPinVersion); err != nil {
		return nil, err
	}
	a.autoPinned = true
	// A server that completes the pinned handshake within the sub-deadline was alive and
	// ignored discover; one that is slow either way was only slow to start, and is offered
	// discover again on its next connect.
	if time.Since(began) < s.opts.DiscoverTimeout {
		s.mu.Lock()
		s.learned = AutoPinVersion
		s.mu.Unlock()
		s.logger.Warn("the server ignores server/discover; keeping the pin", "version", AutoPinVersion)
		if s.opts.OnPinLearned != nil {
			s.opts.OnPinLearned(AutoPinVersion)
		}
	}
	return a, nil
}

// dial starts the transport and runs the MCP handshake offering version ("" for the latest).
func (s *Supervisor) dial(ctx context.Context, version string) (*attempt, error) {
	a := &attempt{sessDone: make(chan struct{})}
	var transport mcp.Transport
	if st := s.opts.Stdio; st != nil {
		proc, err := procutil.Start(procutil.Spec{
			Path: st.Command, Args: st.Args, Dir: st.Dir,
			Env:         procutil.Environ(st.ParentEnv, st.InheritEnv, st.Env),
			Stderr:      s.stderr,
			OOMScoreAdj: procutil.ChildOOMScoreAdj,
		})
		if err != nil {
			return nil, fmt.Errorf("start: %w", err)
		}
		a.proc = proc
		if err := proc.OOMScoreErr(); err != nil {
			s.logger.Warn("cannot raise the child's OOM score", "error", err)
		}
		transport = connTransport{newLineConn(proc.Stdout(), proc.Stdin(), s.opts.MaxMessageBytes, s.logger)}
	} else {
		transport = &mcp.StreamableClientTransport{
			Endpoint:     s.opts.HTTP.URL,
			HTTPClient:   s.http,
			MaxEventSize: s.opts.MaxMessageBytes + frameEdge*4, // the limiter enforces the limit first
		}
	}
	var opts *mcp.ClientSessionOptions
	if version != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: version}
	}
	cs, err := s.client.Connect(ctx, transport, opts)
	if err != nil {
		if a.proc != nil {
			if err := a.proc.Stop(s.opts.StopGrace); err != nil {
				s.logger.Error("child process group did not exit", "error", err)
			}
		}
		if s.httpBase != nil {
			s.httpBase.CloseIdleConnections()
		}
		return nil, fmt.Errorf("connect: %w", err)
	}
	a.session = cs
	go func() {
		a.sessErr = cs.Wait()
		close(a.sessDone)
	}()
	s.mu.Lock()
	s.session, s.version = cs, cs.InitializeResult().ProtocolVersion
	if a.proc != nil {
		s.pid = a.proc.PID()
	}
	s.mu.Unlock()
	s.logger.Info("server connected", "protocolVersion", s.version)
	return a, nil
}

// serve watches a connected session until it ends and returns why.
func (s *Supervisor) serve(base context.Context, a *attempt) error {
	s.setState(Ready)
	var exited <-chan struct{}
	if a.proc != nil {
		exited = a.proc.Done()
	}
	tick := time.NewTicker(s.opts.ProbeInterval)
	defer tick.Stop()
	failures := 0
	for {
		select {
		case <-s.stop:
			return errors.New("stopped")
		case <-a.sessDone:
			return fmt.Errorf("connection closed: %w", a.sessErr)
		case <-exited:
			return fmt.Errorf("process exited: %w", errOrExit(a.proc.ExitErr()))
		case <-tick.C:
		}
		s.mu.Lock()
		busy, calls := s.inflight > 0, s.calls
		s.mu.Unlock()
		if busy {
			continue // a busy single-threaded server would miss the probe
		}
		err := s.probe(base, a.session)
		s.mu.Lock()
		overlapped := s.inflight > 0 || s.calls != calls
		s.mu.Unlock()
		switch {
		case overlapped:
			continue
		case err == nil || isReply(err):
			failures = 0
			s.setState(Ready)
			continue
		}
		failures++
		s.recordError(fmt.Errorf("probe: %w", err))
		s.mu.Lock()
		s.setStateLocked(Degraded)
		restart := failures >= s.opts.ProbeFailures && s.inflight == 0
		if restart {
			s.session = nil // no new call starts on it
		}
		s.mu.Unlock()
		if restart {
			return fmt.Errorf("%d probes in a row failed", failures)
		}
	}
}

func errOrExit(err error) error {
	if err == nil {
		return errors.New("exit status 0")
	}
	return err
}

// probe checks that the server answers: ping on sessions before 2026-07-28, a tools list on
// later ones.
func (s *Supervisor) probe(base context.Context, cs *mcp.ClientSession) error {
	ctx, cancel := context.WithTimeout(base, min(s.opts.ProbeTimeout, s.opts.ProbeInterval))
	defer cancel()
	go func() { // Stop interrupts a probe
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	if cs.InitializeResult().ProtocolVersion >= StatelessVersion {
		_, err := cs.ListTools(ctx, nil)
		return err
	}
	return cs.Ping(ctx, nil)
}

// rejectedByTransport is the code the SDK's HTTP client gives a transport failure it does not
// treat as fatal, such as a 503; it is not a reply from the server.
const rejectedByTransport = -32005

// isReply reports whether err is a JSON-RPC error reply: the server is alive, it only refused.
func isReply(err error) bool {
	var werr *jsonrpc.Error
	return errors.As(err, &werr) && werr.Code != rejectedByTransport
}
