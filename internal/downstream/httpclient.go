package downstream

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// errorBodyLimit bounds the body of an HTTP error response that the SDK reads.
const errorBodyLimit = 64 << 10

// newHTTPClient returns the HTTP client for one server: it adds the configured headers, follows
// no redirects (they would carry the headers elsewhere), and limits every response body and
// event to limit bytes so that an oversized response fails only its own request.
func newHTTPClient(headers map[string]string, limit int, logger *slog.Logger) (*http.Client, *http.Transport) {
	base := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's default transport
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Client{
		Transport: &limitTransport{base: base, headers: h, limit: limit, logger: logger},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, base
}

type limitTransport struct {
	base    http.RoundTripper
	headers http.Header
	limit   int
	logger  *slog.Logger
}

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.headers) > 0 {
		req = req.Clone(req.Context())
		for k, v := range t.headers {
			req.Header[k] = v
		}
	}
	call := sync.OnceValues(func() (jsonrpc.ID, bool) { return callID(req) })
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		resp.Body = limitedBody{io.LimitReader(resp.Body, errorBodyLimit), resp.Body}
	case mediaType == "application/json":
		t.limitJSON(resp, call)
	case mediaType == "text/event-stream":
		resp.Body = &eventLimiter{
			src: resp.Body, br: bufio.NewReaderSize(resp.Body, 64<<10), limit: t.limit,
			call: call, logger: t.logger, lineStart: true,
		}
	}
	return resp, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
}

// callID returns the id of the JSON-RPC request in a POST body, if it is a call. It decodes the
// body, so it is called only for a response over the limit.
func callID(req *http.Request) (jsonrpc.ID, bool) {
	if req.Method != http.MethodPost || req.GetBody == nil {
		return jsonrpc.ID{}, false
	}
	body, err := req.GetBody()
	if err != nil {
		return jsonrpc.ID{}, false
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return jsonrpc.ID{}, false
	}
	msg, err := jsonrpc.DecodeMessage(data)
	if err != nil {
		return jsonrpc.ID{}, false
	}
	if r, ok := msg.(*jsonrpc.Request); ok && r.IsCall() {
		return r.ID, true
	}
	return jsonrpc.ID{}, false
}

// oversizedResponse is the JSON-RPC error that replaces a response over the limit.
func oversizedResponse(id jsonrpc.ID, limit int) []byte {
	data, err := jsonrpc.EncodeMessage(&jsonrpc.Response{ID: id, Error: &jsonrpc.Error{Code: oversizedCode, Message: oversizedMessage(limit)}})
	if err != nil {
		panic(err) // a fixed message always encodes
	}
	return data
}

// limitJSON reads a JSON response of at most limit bytes into memory; a larger one is replaced
// by a JSON-RPC error for the call, which the SDK delivers to that call alone. call returns the
// id of the request, if it is a call.
func (t *limitTransport) limitJSON(resp *http.Response, call func() (jsonrpc.ID, bool)) {
	var buf []byte
	var readErr error
	over := resp.ContentLength > int64(t.limit)
	if !over {
		buf, readErr = io.ReadAll(io.LimitReader(resp.Body, int64(t.limit)+1))
		over = len(buf) > t.limit
	}
	_ = resp.Body.Close()
	if over {
		t.logger.Warn("dropped an HTTP response over maxMessageBytes; its request fails", "limit", t.limit)
		buf, readErr = nil, nil
		if id, isCall := call(); isCall {
			buf = oversizedResponse(id, t.limit)
		} else {
			readErr = errors.New("mcp-gate: the response is larger than maxMessageBytes")
		}
	}
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), errReader{readErr}))
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	if readErr == nil {
		resp.ContentLength = int64(len(buf))
		resp.Header.Set("Content-Length", strconv.Itoa(len(buf)))
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) {
	if r.err == nil {
		return 0, io.EOF
	}
	return 0, r.err
}

// eventLimiter passes a server-sent event stream through one event at a time. An event over the
// limit is dropped; if it was the response to the call that opened the stream, an event holding
// a JSON-RPC error for that call takes its place. A complete event is handed to Read without a
// copy, so the limiter holds it once.
type eventLimiter struct {
	src    io.ReadCloser
	br     *bufio.Reader
	limit  int
	call   func() (jsonrpc.ID, bool) // the id of the request that opened the stream, if it is a call
	logger *slog.Logger

	out       []byte // bytes ready for Read, from off on
	off       int
	cur       []byte    // the event being read
	big       *bigFrame // set while an oversized event is skipped
	lineStart bool
	err       error
}

func (l *eventLimiter) Read(p []byte) (int, error) {
	for len(l.out) == 0 && l.err == nil {
		l.fill()
	}
	if len(l.out) > 0 {
		n := copy(p, l.out[l.off:])
		l.off += n
		if l.off == len(l.out) {
			l.out, l.off = nil, 0 // let the event go once it is read
		}
		return n, nil
	}
	return 0, l.err
}

func (l *eventLimiter) Close() error { return l.src.Close() }

// fill reads the next line of the stream. It is called only when out is empty, and sets out to
// the bytes that line completes.
func (l *eventLimiter) fill() {
	chunk, err := l.br.ReadSlice('\n')
	blank := l.lineStart && (string(chunk) == "\n" || string(chunk) == "\r\n")
	switch {
	case blank && l.big != nil:
		l.replace()
		l.big = nil
		l.out = append(l.out, chunk...)
	case blank:
		l.out = append(l.cur, chunk...) // the event itself, not a copy
		l.cur = nil
	case l.big != nil:
		l.big.size += len(chunk)
		l.big.tail = keepTail(l.big.tail, chunk)
	case len(l.cur)+len(chunk) > l.limit:
		head := bytes.TrimPrefix(bytes.TrimPrefix(dataStart(append(l.cur, chunk...)), []byte("data:")), []byte(" "))
		l.big = &bigFrame{head: append([]byte(nil), head[:min(len(head), frameEdge)]...), size: len(l.cur) + len(chunk)}
		l.big.tail = keepTail(nil, chunk)
		l.cur = nil
	default:
		l.cur = append(l.cur, chunk...)
	}
	l.lineStart = len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
		if l.big == nil && len(l.cur) > 0 {
			l.out = l.cur // the unfinished event; out is empty, since the line was not blank
		}
		l.cur = nil
		l.err = err
	}
}

// dataStart returns event from its first data line on.
func dataStart(event []byte) []byte {
	if bytes.HasPrefix(event, []byte("data:")) {
		return event
	}
	if i := bytes.Index(event, []byte("\ndata:")); i >= 0 {
		return event[i+1:]
	}
	return nil
}

// replace writes the error event for a dropped event that answered the call.
func (l *eventLimiter) replace() {
	id, ok := frameID(l.big)
	want, isCall := l.call()
	if !ok || !isCall || id != want {
		l.logger.Warn("dropped an event over maxMessageBytes that answers no pending request",
			"bytes", l.big.size, "limit", l.limit)
		return
	}
	l.logger.Warn("dropped an event over maxMessageBytes; its request fails", "bytes", l.big.size, "limit", l.limit)
	l.out = append(l.out, "event: message\ndata: "...)
	l.out = append(l.out, oversizedResponse(want, l.limit)...)
	l.out = append(l.out, '\n')
}
