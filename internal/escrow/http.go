package escrow

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const bearerPrefix = "Bearer "

// presentedKey returns the key of an "Authorization: Bearer <key>" header, the scheme in any
// letter case, or "" when the request presents none.
func presentedKey(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerPrefix):])
}

// authorized reports whether key is the API key. Its SHA-256 is compared in constant time.
func (e *Escrow) authorized(key string) bool {
	if key == "" {
		return false
	}
	sum := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(sum[:], e.keyHash[:]) == 1
}

// meta is the answer of GET /_escrow/<handle>/meta. Field names and order are the contract.
type meta struct {
	Handle    string         `json:"handle"`
	Type      string         `json:"type"`
	Kind      string         `json:"kind"`
	Server    string         `json:"server"`
	Tool      string         `json:"tool"`
	Source    map[string]any `json:"source"`
	CreatedAt string         `json:"created_at"`
	ExpiresAt string         `json:"expires_at"`
	Preview   string         `json:"preview"`
	FileName  string         `json:"file_name,omitempty"`
	Size      *int64         `json:"size,omitempty"`
}

// Handler serves the API under Route:
//
//	GET    /_escrow/<handle>/meta  metadata as JSON (HEAD: headers only)
//	GET    /_escrow/<handle>       the value, as application/octet-stream
//	DELETE /_escrow/<handle>       drops the entry: 204
//
// Every answer carries Cache-Control: no-store. Without the key the answer is 401, whatever the
// path; a client with too many failed attempts gets 429 first.
func (e *Escrow) Handler() http.Handler { return http.HandlerFunc(e.serveHTTP) }

func (e *Escrow) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rest := strings.TrimPrefix(r.URL.Path, Route)
	handle, sub, _ := strings.Cut(rest, "/")
	status := http.StatusOK
	op := "value"
	if sub == "meta" {
		op = "meta"
	} else if r.Method == http.MethodDelete {
		op = "delete"
	}
	logHandle := handle
	if !HandleRE.MatchString(handle) {
		logHandle = "<invalid>"
	}
	client := e.remote(r)
	defer func() {
		e.logger.Info("escrow access", "op", op, "handle", logHandle, "status", status, "remote", client)
	}()

	if wait, ok := e.limit.allow(client); !ok {
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		http.Error(w, "Too Many Requests", status)
		return
	}
	if key := presentedKey(r); !e.authorized(key) {
		if key != "" {
			e.limit.fail(client) // only a presented key can be a guess
		}
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="escrow"`)
		http.Error(w, "Unauthorized", status)
		return
	}
	if !HandleRE.MatchString(handle) || (sub != "" && sub != "meta") {
		status = http.StatusNotFound
		http.Error(w, "Not Found", status)
		return
	}

	switch {
	case sub == "meta" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		ent, ok := e.store.get(handle)
		if !ok {
			status = http.StatusNotFound
			http.Error(w, "Not Found", status)
			return
		}
		m := meta{
			Handle: ent.handle, Type: ent.kind, Kind: "text", Server: ent.server, Tool: ent.tool,
			Source:    ent.source,
			CreatedAt: ent.created.UTC().Format(time.RFC3339),
			ExpiresAt: ent.expires.UTC().Format(time.RFC3339),
			Preview:   preview(ent.value),
		}
		if ent.file != nil {
			m.Kind, m.Preview, m.FileName = "file", "", ent.file.name
			size := ent.file.size
			m.Size = &size
		}
		if m.Source == nil {
			m.Source = map[string]any{}
		}
		clear(ent.value)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}
		if err := json.NewEncoder(w).Encode(m); err != nil {
			e.logger.Warn("escrow meta not written", "error", err.Error())
		}
	case sub == "" && r.Method == http.MethodGet:
		ent, ok := e.store.get(handle)
		if !ok {
			status = http.StatusNotFound
			http.Error(w, "Not Found", status)
			return
		}
		value := ent.value
		if ent.file != nil {
			content, err := readFile(ent.file)
			if err != nil {
				e.logger.Warn("escrowed file unavailable", "handle", handle, "reason", err.Error())
				status = http.StatusNotFound
				http.Error(w, "Not Found", status)
				return
			}
			value = content
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(value)))
		_, _ = w.Write(value)
		clear(value)
	case sub == "" && r.Method == http.MethodDelete:
		if !e.store.remove(handle) {
			status = http.StatusNotFound
			http.Error(w, "Not Found", status)
			return
		}
		status = http.StatusNoContent
		w.WriteHeader(status)
	default:
		status = http.StatusMethodNotAllowed
		http.Error(w, "Method Not Allowed", status)
	}
}

// peer is the request's peer address without the port.
func peer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
