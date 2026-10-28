package downstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// oversizedCode is the JSON-RPC error code of a response that was too large.
const oversizedCode = jsonrpc.CodeInternalError

// oversizedMessage is the error message of a response that was too large.
func oversizedMessage(limit int) string {
	return fmt.Sprintf("mcp-gate: the server's response is larger than maxMessageBytes (%d bytes) and was dropped", limit)
}

// lineConn is an mcp.Connection over newline-delimited JSON on a child's stdin and stdout.
//
// Unlike the SDK's stdio transport, a frame longer than the limit does not end the connection:
// it is skipped up to the next newline, and if it was the response to a pending request, that
// request gets a JSON-RPC error instead. Lines that are not JSON-RPC messages (stray output on
// stdout) are skipped with a warning.
type lineConn struct {
	r      io.ReadCloser
	w      io.WriteCloser
	limit  int
	logger *slog.Logger

	incoming chan jsonrpc.Message
	readErr  chan error // receives the error that ended the read loop
	closed   chan struct{}

	closeOnce sync.Once
	writeMu   sync.Mutex

	pendingMu sync.Mutex
	pending   map[jsonrpc.ID]bool // requests sent and not yet answered
}

var _ mcp.Connection = (*lineConn)(nil)

func newLineConn(r io.ReadCloser, w io.WriteCloser, limit int, logger *slog.Logger) *lineConn {
	c := &lineConn{
		r: r, w: w, limit: limit, logger: logger,
		incoming: make(chan jsonrpc.Message),
		readErr:  make(chan error, 1),
		closed:   make(chan struct{}),
		pending:  map[jsonrpc.ID]bool{},
	}
	go c.readLoop()
	return c
}

// connTransport hands an existing connection to mcp.Client.Connect.
type connTransport struct{ conn mcp.Connection }

func (t connTransport) Connect(context.Context) (mcp.Connection, error) { return t.conn, nil }

func (c *lineConn) SessionID() string { return "" }

func (c *lineConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case m := <-c.incoming:
		return m, nil
	case err := <-c.readErr:
		c.readErr <- err // keep it for later reads
		return nil, err
	case <-c.closed:
		return nil, mcp.ErrConnectionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *lineConn) Write(_ context.Context, msg jsonrpc.Message) error {
	data, err := jsonrpc.EncodeMessage(msg)
	if err != nil {
		return err
	}
	if req, ok := msg.(*jsonrpc.Request); ok {
		c.pendingMu.Lock()
		if req.IsCall() {
			c.pending[req.ID] = true
		} else if id, ok := cancelledID(req); ok {
			delete(c.pending, id) // a cancelled request may never be answered
		}
		c.pendingMu.Unlock()
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.closed:
		return mcp.ErrConnectionClosed
	default:
	}
	_, err = c.w.Write(append(data, '\n'))
	return err
}

func (c *lineConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.w.Close()
		_ = c.r.Close()
	})
	return nil
}

// deliver hands m to Read, unless the connection is closed first.
func (c *lineConn) deliver(m jsonrpc.Message) bool {
	if resp, ok := m.(*jsonrpc.Response); ok {
		c.pendingMu.Lock()
		delete(c.pending, resp.ID)
		c.pendingMu.Unlock()
	}
	select {
	case c.incoming <- m:
		return true
	case <-c.closed:
		return false
	}
}

func (c *lineConn) readLoop() {
	br := bufio.NewReaderSize(c.r, 64<<10)
	for {
		line, big, err := readFrame(br, c.limit)
		if big != nil {
			if !c.oversized(big) {
				return
			}
		} else if len(bytes.TrimSpace(line)) > 0 {
			for _, m := range c.decode(line) {
				if !c.deliver(m) {
					return
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.EOF
			}
			c.readErr <- err
			return
		}
	}
}

// decode parses a line holding one message or a batch. Lines that do not decode are skipped.
func (c *lineConn) decode(line []byte) []jsonrpc.Message {
	line = bytes.TrimSpace(line)
	if line[0] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(line, &raws); err != nil {
			c.logger.Warn("skipped a line on stdout that is not JSON-RPC", "bytes", len(line))
			return nil
		}
		var out []jsonrpc.Message
		for _, raw := range raws {
			out = append(out, c.decode(raw)...)
		}
		return out
	}
	m, err := jsonrpc.DecodeMessage(line)
	if err != nil {
		c.logger.Warn("skipped a line on stdout that is not JSON-RPC", "bytes", len(line))
		return nil
	}
	return []jsonrpc.Message{m}
}

// cancelledID returns the request a notifications/cancelled names.
func cancelledID(req *jsonrpc.Request) (jsonrpc.ID, bool) {
	if req.Method != "notifications/cancelled" {
		return jsonrpc.ID{}, false
	}
	var p struct {
		RequestID any `json:"requestId"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return jsonrpc.ID{}, false
	}
	id, err := jsonrpc.MakeID(p.RequestID)
	return id, err == nil
}

// oversized handles a frame that was too long: a pending request it answers gets an error.
func (c *lineConn) oversized(f *bigFrame) bool {
	id, ok := frameID(f)
	if ok {
		c.pendingMu.Lock()
		ok = c.pending[id]
		c.pendingMu.Unlock()
	}
	if !ok {
		c.logger.Warn("dropped a message over maxMessageBytes that answers no pending request",
			"bytes", f.size, "limit", c.limit)
		return true
	}
	c.logger.Warn("dropped a response over maxMessageBytes; its request fails",
		"bytes", f.size, "limit", c.limit)
	return c.deliver(&jsonrpc.Response{ID: id, Error: &jsonrpc.Error{Code: oversizedCode, Message: oversizedMessage(c.limit)}})
}

// bigFrame is what is kept of a frame over the limit: its start and end, to find its id.
type bigFrame struct {
	head, tail []byte
	size       int
}

const frameEdge = 1 << 10

// readFrame reads one line. A line whose frame (the line without its "\n" or "\r\n") is longer
// than limit is consumed up to its newline and returned as a bigFrame instead, so it never takes
// more than limit bytes of memory and its line ending.
func readFrame(br *bufio.Reader, limit int) ([]byte, *bigFrame, error) {
	var line []byte
	var big *bigFrame
	for {
		chunk, err := br.ReadSlice('\n')
		if big == nil && len(line)+len(chunk) > limit+len("\r\n") {
			big = newBigFrame(line)
			line = nil
		}
		if big != nil {
			big.add(chunk)
		} else {
			line = append(line, chunk...)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if big == nil && len(trimLineEnding(line)) > limit {
				big = newBigFrame(line)
				line = nil
			}
			return line, big, err
		}
	}
}

// trimLineEnding returns line without its "\n" or "\r\n".
func trimLineEnding(line []byte) []byte {
	if bytes.HasSuffix(line, []byte("\r\n")) {
		return line[:len(line)-2]
	}
	return bytes.TrimSuffix(line, []byte("\n"))
}

// newBigFrame starts a bigFrame with the bytes of a frame read so far.
func newBigFrame(line []byte) *bigFrame {
	return &bigFrame{
		head: append([]byte(nil), line[:min(len(line), frameEdge)]...),
		tail: keepTail(nil, line[max(0, len(line)-frameEdge):]),
		size: len(line),
	}
}

// add counts the next chunk of a frame and keeps what its head and tail need.
func (f *bigFrame) add(chunk []byte) {
	if n := frameEdge - len(f.head); n > 0 {
		f.head = append(f.head, chunk[:min(len(chunk), n)]...)
	}
	f.size += len(chunk)
	f.tail = keepTail(f.tail, chunk)
}

// keepTail appends chunk to tail and keeps the last frameEdge bytes.
func keepTail(tail, chunk []byte) []byte {
	tail = append(tail, chunk...)
	if len(tail) > frameEdge {
		tail = append([]byte(nil), tail[len(tail)-frameEdge:]...)
	}
	return tail
}

var (
	// headIDRE finds the id at the start of a message: {"jsonrpc":"2.0","id":7,...
	headIDRE = regexp.MustCompile(`^\s*\{\s*(?:"jsonrpc"\s*:\s*"2\.0"\s*,\s*)?"id"\s*:\s*(-?[0-9]+|"(?:[^"\\]|\\.)*")\s*,`)
	// tailIDRE finds the id at the end of a message: ...,"jsonrpc":"2.0","id":7}
	tailIDRE = regexp.MustCompile(`,\s*"id"\s*:\s*(-?[0-9]+|"(?:[^"\\]|\\.)*")\s*(?:,\s*"jsonrpc"\s*:\s*"2\.0"\s*)?\}\s*$`)
)

// frameID finds the id of a truncated message from its first or last bytes. Servers write the
// id either first (most) or last (the TypeScript SDK).
func frameID(f *bigFrame) (jsonrpc.ID, bool) {
	if !isResponse(f.head) {
		return jsonrpc.ID{}, false
	}
	for _, m := range [][][]byte{headIDRE.FindSubmatch(f.head), tailIDRE.FindSubmatch(f.tail)} {
		if m == nil {
			continue
		}
		var v any
		if err := json.Unmarshal(m[1], &v); err != nil {
			continue
		}
		id, err := jsonrpc.MakeID(v)
		if err == nil {
			return id, true
		}
	}
	return jsonrpc.ID{}, false
}

// isResponse reports whether the start of a message shows a response: a top-level "result" or
// "error" member before any "method". A request from the server carries an id from the
// server's own sequence, which must not fail the gate's request of the same number.
func isResponse(head []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(head))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	for {
		key, err := dec.Token()
		if err != nil {
			return false
		}
		switch key {
		case "result", "error":
			return true
		case "method":
			return false
		}
		if !skipValue(dec) {
			return false
		}
	}
}

// skipValue reads one JSON value from dec.
func skipValue(dec *json.Decoder) bool {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return true
		}
	}
}
