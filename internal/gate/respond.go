package gate

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/segmentio/encoding/json"

	"github.com/vsem-azamat/mcp-gate/internal/upstream"
)

// bodyKind is what a POST body holds, as far as choosing its response goes.
type bodyKind int

const (
	// bodyStream needs an event stream, or may: a batch, a request with a progress token, or a
	// body the gate does not read.
	bodyStream bodyKind = iota
	// bodyPlain is one JSON-RPC message without a progress token: its answer is the response alone.
	bodyPlain
	// bodyListen is a subscriptions/listen request, a stream that stays open.
	bodyListen
)

// methodListen is the method of a 2026-07-28 client's long-lived stream of notifications.
const methodListen = "subscriptions/listen"

// bothAccepted is the Accept header the SDK's handler requires, given to it in place of a
// client's that names only the type the gate answers with.
const bothAccepted = "application/json, text/event-stream"

// respond serves a request with stream, the SDK's handler that answers with an event stream, or
// with plain, the one that answers with plain JSON. The only messages the gate sends on a
// request's stream besides its response are progress notifications, and only when the request
// carries a progress token (a stateless server makes no requests of the client, and list-changed
// notifications go to subscriptions/listen streams), so a single message without one is answered
// with plain JSON when the client accepts it. A client that accepts only one of the two types gets
// that one. A subscriptions/listen request is also cancelled when shutdown begins. ReadBody must
// have read the body.
func (g *Gate) respond(stream, plain http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := bodyStream
		if body, ok := upstream.BodyBytes(r); ok {
			kind = classify(body)
		}
		if kind == bodyListen {
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			go func() {
				select {
				case <-g.drain:
					cancel()
				case <-ctx.Done():
				}
			}()
			r = r.WithContext(ctx)
		}
		if r.Method != http.MethodPost {
			stream.ServeHTTP(w, r)
			return
		}
		jsonOK, streamOK := accepts(r.Header.Values("Accept"))
		usePlain := jsonOK && (kind == bodyPlain || (!streamOK && kind != bodyListen))
		switch {
		case !usePlain && !streamOK && kind == bodyListen:
			http.Error(w, "Accept must admit text/event-stream for subscriptions/listen", http.StatusBadRequest)
			return
		case !usePlain && !streamOK:
			http.Error(w, "Accept must admit application/json or text/event-stream", http.StatusBadRequest)
			return
		case (usePlain && !streamOK) || (!usePlain && !jsonOK):
			// The SDK's handler requires both; the client gets the one it accepts.
			r = r.Clone(r.Context())
			r.Header.Set("Accept", bothAccepted)
		}
		if usePlain {
			plain.ServeHTTP(w, r)
			return
		}
		stream.ServeHTTP(w, r)
	})
}

// classify tells what body holds. A JSON object that holds neither "progressToken" nor "listen"
// (which subscriptions\/listen spells too) nor a \u escape, which could spell either, is plain
// without decoding it. Any other is decoded as the SDK decodes it (see decodeExact), so that it
// finds the progress token the SDK finds.
func classify(body []byte) bodyKind {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return bodyStream
	}
	if !bytes.Contains(body, []byte("progressToken")) && !bytes.Contains(body, []byte("listen")) &&
		!bytes.Contains(body, []byte(`\u`)) {
		return bodyPlain
	}
	var msg struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if decodeExact(body, &msg) != nil {
		return bodyStream
	}
	if msg.Method == methodListen {
		return bodyListen
	}
	if len(msg.Params) == 0 {
		return bodyPlain
	}
	var params struct {
		Meta map[string]any `json:"_meta"`
	}
	if decodeExact(msg.Params, &params) != nil {
		return bodyStream
	}
	if _, ok := params.Meta["progressToken"]; ok {
		return bodyStream
	}
	return bodyPlain
}

// decodeExact decodes data into v the way the SDK decodes messages: with segmentio's decoder,
// matching struct field names exactly, and merging a repeated object key into the same map.
func decodeExact(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DontMatchCaseInsensitiveStructFields()
	return dec.Decode(v)
}

// accepts reports whether an Accept header admits application/json and text/event-stream, read
// as the SDK reads it (media types and the wildcards), except that a type given q=0 is refused:
// a wildcard with q=0 admits nothing, and a specific type with q=0 is refused despite a wildcard.
func accepts(values []string) (jsonOK, streamOK bool) {
	var jsonNo, streamNo bool
	for _, value := range values {
		for raw := range strings.SplitSeq(value, ",") {
			base, params, _ := strings.Cut(raw, ";")
			no := refused(params)
			switch strings.ToLower(strings.TrimSpace(base)) {
			case "application/json":
				jsonOK, jsonNo = jsonOK || !no, jsonNo || no
			case "text/event-stream":
				streamOK, streamNo = streamOK || !no, streamNo || no
			case "application/*":
				jsonOK = jsonOK || !no
			case "text/*":
				streamOK = streamOK || !no
			case "*/*":
				jsonOK, streamOK = jsonOK || !no, streamOK || !no
			}
		}
	}
	return jsonOK && !jsonNo, streamOK && !streamNo
}

// refused reports whether the parameters of an Accept entry give it a quality of zero.
func refused(params string) bool {
	for p := range strings.SplitSeq(params, ";") {
		k, v, _ := strings.Cut(p, "=")
		if strings.EqualFold(strings.TrimSpace(k), "q") {
			q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return err == nil && q == 0
		}
	}
	return false
}
