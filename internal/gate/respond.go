package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

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
		jsonOK, streamOK := accepts(r.Header.Values("Accept"))
		usePlain := jsonOK && (kind == bodyPlain || (!streamOK && kind != bodyListen))
		switch {
		case !usePlain && !streamOK:
			// An event stream the client does not accept: neither type, or subscriptions/listen
			// accepting only JSON. The SDK, which reads no q=0, refuses a request without Accept.
			r = r.Clone(r.Context())
			r.Header.Del("Accept")
		case (usePlain && !streamOK) || (!usePlain && !jsonOK):
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
// without decoding it; any other is decoded with exact key names, as the SDK decodes it.
func classify(body []byte) bodyKind {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return bodyStream
	}
	if !bytes.Contains(body, []byte("progressToken")) && !bytes.Contains(body, []byte("listen")) &&
		!bytes.Contains(body, []byte(`\u`)) {
		return bodyPlain
	}
	// Maps, unlike structs, match keys exactly.
	var msg, params map[string]json.RawMessage
	var method string
	if json.Unmarshal(body, &msg) != nil {
		return bodyStream
	}
	if m, ok := msg["method"]; ok && json.Unmarshal(m, &method) != nil {
		return bodyStream
	}
	if method == methodListen {
		return bodyListen
	}
	if p, ok := msg["params"]; ok && json.Unmarshal(p, &params) != nil {
		return bodyStream
	}
	var meta map[string]json.RawMessage
	if m, ok := params["_meta"]; ok && json.Unmarshal(m, &meta) != nil {
		return bodyStream
	}
	if _, ok := meta["progressToken"]; ok {
		return bodyStream
	}
	return bodyPlain
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
