package procutil

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

// LineLog logs a child's stderr line by line, rate limited, and keeps the most recent lines in a
// ring buffer for status pages. One LineLog may outlive several processes of the same server.
type LineLog struct {
	logger *slog.Logger
	filter func(string) string
	onLine func()

	mu       sync.Mutex
	ring     []string
	ringSize int // bytes in ring, each line counted with its newline, so that empty lines count
	ringMax  int
	tokens   float64
	last     time.Time
	dropped  int
}

// Limits of a LineLog.
const (
	// MaxLineBytes is the longest line kept; the rest of a longer line is dropped.
	MaxLineBytes = 4 << 10
	// readBytes is how much of a line is read and redacted before it is cut, so that a secret
	// across the cut is still found. Of a line longer than that, only the start that the filter
	// turns into the same text with and without the last cutMargin bytes read is kept: a secret
	// that ends past the read is not seen whole, and its start may be in those bytes.
	readBytes = 2 * MaxLineBytes
	cutMargin = 256
	// DefaultTailBytes is the default size of the ring buffer.
	DefaultTailBytes = 64 << 10
	// lineRate and lineBurst limit how many lines per second reach the log.
	lineRate  = 20
	lineBurst = 100
)

// NewLineLog returns a LineLog that writes to logger. filter, if not nil, rewrites every line
// before it is logged or kept (for redaction). tailBytes bounds the ring buffer; 0 means
// DefaultTailBytes. onLine, if not nil, is called after each line is kept, without the
// LineLog's lock held, so that a status that shows Tail can be watched.
func NewLineLog(logger *slog.Logger, filter func(string) string, tailBytes int, onLine func()) *LineLog {
	if tailBytes <= 0 {
		tailBytes = DefaultTailBytes
	}
	if filter == nil {
		filter = func(s string) string { return s }
	}
	return &LineLog{logger: logger, filter: filter, onLine: onLine, ringMax: tailBytes, tokens: lineBurst}
}

// Consume reads r to its end, one line at a time.
func (l *LineLog) Consume(r io.Reader) {
	br := bufio.NewReaderSize(r, readBytes)
	for {
		line, err := br.ReadSlice('\n')
		truncated := errors.Is(err, bufio.ErrBufferFull)
		if len(line) > 0 {
			l.add(trimEOL(line), truncated)
		}
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = br.ReadSlice('\n') // drop the rest of a long line
		}
		if err != nil {
			return
		}
	}
}

func trimEOL(b []byte) string {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return string(b)
}

func (l *LineLog) add(line string, truncated bool) {
	if truncated {
		line = scannedStart(l.filter, line)
	} else {
		line = l.filter(line)
	}
	if len(line) > MaxLineBytes {
		line, truncated = line[:MaxLineBytes], true
	}
	if truncated {
		line += " [truncated]"
	}
	l.mu.Lock()
	l.ring = append(l.ring, line)
	l.ringSize += len(line) + 1
	for l.ringSize > l.ringMax && len(l.ring) > 1 {
		l.ringSize -= len(l.ring[0]) + 1
		l.ring = l.ring[1:]
	}
	now := time.Now()
	if !l.last.IsZero() {
		l.tokens = min(lineBurst, l.tokens+now.Sub(l.last).Seconds()*lineRate)
	}
	l.last = now
	allowed := l.tokens >= 1
	var dropped int
	if allowed {
		l.tokens--
		dropped, l.dropped = l.dropped, 0
	} else {
		l.dropped++
	}
	l.mu.Unlock()
	if l.onLine != nil {
		l.onLine()
	}
	if !allowed {
		return
	}
	if dropped > 0 {
		l.logger.Warn("child stderr lines dropped by the rate limit", "count", dropped)
	}
	l.logger.Info("child stderr", "line", line)
}

// scannedStart filters the start of a line that was cut at the read. It filters the line as read
// and without its last cutMargin bytes, and returns the longest start the two agree on. That
// start is a start of the line filtered without the margin, so it holds no part of a secret of
// up to cutMargin bytes that continues past the read; and a secret that ends inside the margin,
// which only the whole read shows, is redacted in the first and not in the second, so the start
// ends before it. This holds however much the filter shrinks or grows the text.
func scannedStart(filter func(string) string, line string) string {
	whole, short := filter(line), filter(line[:len(line)-cutMargin])
	n := 0
	for n < len(whole) && n < len(short) && whole[n] == short[n] {
		n++
	}
	return whole[:n]
}

// Tail returns the most recent lines, oldest first.
func (l *LineLog) Tail() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ring...)
}
