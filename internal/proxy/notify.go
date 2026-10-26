package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
	"github.com/vsem-azamat/mcp-gate/internal/redact/mcpredact"
)

// eventQueue is the size of a mirror's notification queue. A notification that finds it full is
// dropped: the SDK delivers notifications one at a time, so a handler that waited would hold up
// every later one from the server.
const eventQueue = 64

// event is a downstream notification waiting for the worker.
type event struct {
	progress *mcp.ProgressNotificationParams
	log      *mcp.LoggingMessageParams //nolint:staticcheck // servers of older protocol versions still send log messages
}

func (s *Source) enqueue(e event) {
	select {
	case s.events <- e:
	default:
		s.stats.dropped.Add(1)
	}
}

// notifyLoop hands progress to the call it belongs to and logs log messages, scrubbed as the
// mirror that runs the call, or the current one, scrubs.
func (s *Source) notifyLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.events:
			safely(s.logger, "notification", func() {
				switch {
				case e.progress != nil:
					s.progress.deliver(e.progress)
				case e.log != nil:
					if m := s.current(); m != nil {
						m.logMessage(ctx, e.log)
					}
				}
			})
		}
	}
}

// logMessage logs a server's log message at debug level, redacted.
func (m *Mirror) logMessage(ctx context.Context, p *mcp.LoggingMessageParams) { //nolint:staticcheck // servers of older protocol versions still send log messages
	if !m.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	data, err := json.Marshal(p.Data)
	if err != nil {
		return
	}
	text := redact.Cut(m.scrub(string(data)), 4096)
	m.logger.DebugContext(ctx, "server log message", "level", m.logText(string(p.Level)), "logger", m.logText(p.Logger), "data", text)
}

// progressTable maps the progress tokens sent downstream to the upstream calls they belong to. A
// source has one, shared by the mirrors of every config the server is served under.
type progressTable struct {
	next  atomic.Uint64
	mu    sync.Mutex
	sinks map[string]*progressSink
}

func newProgressTable() *progressTable { return &progressTable{sinks: map[string]*progressSink{}} }

// progressSink delivers progress to one upstream call. It keeps only the latest notification
// not yet sent, and sends from a goroutine of its own, so that a client that does not read its
// stream holds up only its own call.
type progressSink struct {
	id    string
	ctx   context.Context // the upstream request's: it routes the notification to its stream
	ss    *mcp.ServerSession
	token any
	scrub func(string) string // the redaction of the call's mirror

	mu      sync.Mutex
	pending *mcp.ProgressNotificationParams
	wake    chan struct{}
	done    chan struct{}
}

func (t *progressTable) open(ctx context.Context, ss *mcp.ServerSession, token any, scrub func(string) string, logger *slog.Logger) *progressSink {
	t.mu.Lock()
	s := &progressSink{
		id: "mcp-gate-" + strconv.FormatUint(t.next.Add(1), 10), ctx: ctx, ss: ss, token: token, scrub: scrub,
		wake: make(chan struct{}, 1), done: make(chan struct{}),
	}
	t.sinks[s.id] = s
	t.mu.Unlock()
	go s.run(logger)
	return s
}

// close removes the sink when its call ends. Progress still pending is dropped.
func (t *progressTable) close(s *progressSink) {
	t.mu.Lock()
	delete(t.sinks, s.id)
	t.mu.Unlock()
	close(s.done)
}

// deliver passes p to the call whose downstream token it carries; others are dropped.
func (t *progressTable) deliver(p *mcp.ProgressNotificationParams) {
	id, ok := p.ProgressToken.(string)
	if !ok {
		return
	}
	t.mu.Lock()
	s := t.sinks[id]
	t.mu.Unlock()
	if s == nil {
		return
	}
	q := *p
	if q.Message != "" {
		q.Message = s.scrub(q.Message)
	}
	s.mu.Lock()
	s.pending = &q
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *progressSink) run(logger *slog.Logger) {
	for {
		select {
		case <-s.done:
			return
		case <-s.wake:
		}
		s.mu.Lock()
		p := s.pending
		s.pending = nil
		s.mu.Unlock()
		if p == nil {
			continue
		}
		up := &mcp.ProgressNotificationParams{ProgressToken: s.token, Progress: p.Progress, Total: p.Total, Message: p.Message}
		safely(logger, "progress", func() {
			if err := s.ss.NotifyProgress(s.ctx, up); err != nil {
				logger.Debug("progress not delivered", "error", err.Error())
			}
		})
	}
}

// Request describes the call whose result is redacted, for a replacer that keeps values.
type Request struct {
	// Method is tools/call, prompts/get or resources/read.
	Method string
	// Name is the tool or prompt name, or the resource URI.
	Name string
	// Arguments returns the call's arguments, decoded once; nil when there are none.
	Arguments func() map[string]any
}

// ReplacerFunc returns the replacer for the findings in one call's result.
type ReplacerFunc func(Request) redact.Replacer

// Redaction is the result pipeline of one server.
type Redaction struct {
	engine   *redact.Engine
	results  *mcpredact.Redactor
	replacer ReplacerFunc
}

// NewRedaction returns the pipeline for engine. Findings in results are replaced by what the
// replacer for their call returns, [REDACTED:<kind>] when replacer is nil; findings in texts
// outside results, such as progress messages, by [REDACTED:<kind>]. A text over maxTextBytes
// fails its result.
func NewRedaction(engine *redact.Engine, replacer ReplacerFunc, maxTextBytes int) *Redaction {
	if replacer == nil {
		replacer = func(Request) redact.Replacer { return redact.Marker{} }
	}
	return &Redaction{engine: engine, results: mcpredact.New(engine, maxTextBytes), replacer: replacer}
}

// FileScanner checks the files a tool call wrote; see package filescan.
type FileScanner interface {
	// Scan returns res with the files that hold secrets withheld, and how many were. An error
	// means a file could not be scanned, and the result is withheld.
	Scan(ctx context.Context, tool string, args func() map[string]any, res *mcp.CallToolResult, start time.Time) (*mcp.CallToolResult, int, error)
}

// counter counts the findings of one call.
type counter struct{ n atomic.Int64 }

// countingReplacer counts the findings it replaces.
type countingReplacer struct {
	next redact.Replacer
	n    *counter
}

func (r *countingReplacer) Replace(f redact.Finding) string {
	r.n.n.Add(1)
	return r.next.Replace(f)
}

// safely runs fn and logs a panic in it by type, so that one bad notification does not end the
// gate.
func safely(logger *slog.Logger, what string, fn func()) {
	defer func() {
		if v := recover(); v != nil {
			logger.Error("panic while handling a "+what, "type", fmt.Sprintf("%T", v))
		}
	}()
	fn()
}
