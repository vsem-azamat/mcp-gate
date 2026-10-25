package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

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

func (m *Mirror) enqueue(e event) {
	select {
	case m.events <- e:
	default:
		m.stats.dropped.Add(1)
	}
}

// notifyLoop hands progress to the call it belongs to and logs log messages.
func (m *Mirror) notifyLoop(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.events:
			switch {
			case e.progress != nil:
				p := *e.progress
				if p.Message != "" {
					p.Message = m.scrub(p.Message)
				}
				m.progress.deliver(&p)
			case e.log != nil:
				m.logMessage(ctx, e.log)
			}
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
	text := m.scrub(string(data))
	if len(text) > 4096 {
		text = text[:4096] + "…"
	}
	m.logger.DebugContext(ctx, "server log message", "level", string(p.Level), "logger", p.Logger, "data", text)
}

// progressTable maps the progress tokens sent downstream to the upstream calls they belong to.
type progressTable struct {
	mu    sync.Mutex
	next  uint64
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

	mu      sync.Mutex
	pending *mcp.ProgressNotificationParams
	wake    chan struct{}
	done    chan struct{}
}

func (t *progressTable) open(ctx context.Context, ss *mcp.ServerSession, token any, logger *slog.Logger) *progressSink {
	t.mu.Lock()
	t.next++
	s := &progressSink{
		id: "mcp-gate-" + strconv.FormatUint(t.next, 10), ctx: ctx, ss: ss, token: token,
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
	s.mu.Lock()
	s.pending = p
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
		if err := s.ss.NotifyProgress(s.ctx, up); err != nil {
			logger.Debug("progress not delivered", "error", err.Error())
		}
	}
}

// Redaction is the result pipeline of one server.
type Redaction struct {
	engine   *redact.Engine
	results  *mcpredact.Redactor
	replacer redact.Replacer
}

// NewRedaction returns the pipeline for engine. Findings are replaced by what replacer returns;
// a text over maxTextBytes fails its result.
func NewRedaction(engine *redact.Engine, replacer redact.Replacer, maxTextBytes int) *Redaction {
	if replacer == nil {
		replacer = redact.Marker{}
	}
	return &Redaction{engine: engine, results: mcpredact.New(engine, maxTextBytes), replacer: replacer}
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
