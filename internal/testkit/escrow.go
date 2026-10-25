package testkit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// EscrowTarget is an escrow API under test, holding one live text entry.
type EscrowTarget struct {
	// Base is the listener's URL, such as http://127.0.0.1:9090.
	Base   string
	Key    string
	Handle string
	// Secret is the entry's value.
	Secret string
	// Meta holds the meta fields expected besides handle, kind and the times: type, server,
	// tool, source and preview.
	Meta map[string]any
	// TTL is the entry's expected lifetime.
	TTL time.Duration
}

// escrowMetaKeys are the members of a text entry's meta, in the order the contract writes them.
var escrowMetaKeys = []string{"handle", "type", "kind", "server", "tool", "source", "created_at", "expires_at", "preview"}

// CheckEscrowContract checks the escrow HTTP contract against target: the auth scheme, the
// paths and methods, the status codes, bodies and headers, and the meta document. It is the
// contract of the mcp-proxy fork's escrow; it deletes the entry at the end, and fails twelve
// authentications from the caller's address on the way.
func CheckEscrowContract(t *testing.T, target EscrowTarget) {
	t.Helper()
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path, auth string) (int, http.Header, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, target.Base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, res.Header, body
	}
	plain := func(what string, code int, h http.Header, body []byte, wantCode int, wantBody string) {
		t.Helper()
		if code != wantCode || string(body) != wantBody || h.Get("Content-Type") != "text/plain; charset=utf-8" ||
			h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s = %d %q %v, want %d %q as text/plain, nosniff, no-store", what, code, body, h, wantCode, wantBody)
		}
	}
	handlePath := "/_escrow/" + target.Handle
	metaPath := handlePath + "/meta"
	auth := "Bearer " + target.Key

	// A wrong or missing key, the bare key and a client token: 401, even for unknown handles.
	for _, bad := range []string{"", "Bearer nope", auth + "x", target.Key} {
		for _, path := range []string{metaPath, handlePath, "/_escrow/kaaaaaaaaaa"} {
			code, h, body := do(http.MethodGet, path, bad)
			plain("GET "+path+" with a bad key", code, h, body, http.StatusUnauthorized, "Unauthorized\n")
			if got := h.Get("WWW-Authenticate"); got != `Bearer realm="escrow"` {
				t.Errorf("WWW-Authenticate = %q", got)
			}
		}
	}

	// The scheme is matched without regard to case.
	code, h, body := do(http.MethodGet, metaPath, "bearer "+target.Key)
	if code != http.StatusOK || h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("meta = %d %v %s", code, h, body)
	}
	if bytes.Contains(body, []byte(target.Secret)) {
		t.Error("meta holds the value")
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		t.Errorf("meta is not one JSON line: %q", body)
	}
	if keys := jsonKeys(t, body); !reflect.DeepEqual(keys, escrowMetaKeys) {
		t.Errorf("meta members = %v, want %v", keys, escrowMetaKeys)
	}
	var meta map[string]any
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"handle": target.Handle, "kind": "text"}
	for k, v := range target.Meta {
		want[k] = v
	}
	for k, v := range want {
		if !reflect.DeepEqual(meta[k], v) {
			t.Errorf("meta[%s] = %#v, want %#v", k, meta[k], v)
		}
	}
	created, err1 := time.Parse(time.RFC3339, str(meta["created_at"]))
	expires, err2 := time.Parse(time.RFC3339, str(meta["expires_at"]))
	if err1 != nil || err2 != nil || created.Location() != time.UTC || created.Nanosecond() != 0 ||
		expires.Sub(created) < target.TTL-time.Minute || expires.Sub(created) > target.TTL+time.Minute {
		t.Errorf("created_at/expires_at = %v / %v, want UTC seconds %s apart", meta["created_at"], meta["expires_at"], target.TTL)
	}

	code, h, body = do(http.MethodHead, metaPath, auth)
	if code != http.StatusOK || h.Get("Content-Type") != "application/json" || len(body) != 0 {
		t.Errorf("HEAD meta = %d %v %q", code, h, body)
	}

	code, h, body = do(http.MethodGet, handlePath, auth)
	if code != http.StatusOK || string(body) != target.Secret || h.Get("Content-Type") != "application/octet-stream" ||
		h.Get("Content-Length") != strconv.Itoa(len(target.Secret)) || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("value = %d %v %q", code, h, body)
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, handlePath},
		{http.MethodPut, handlePath},
		{http.MethodDelete, metaPath},
		{http.MethodPost, metaPath},
		{http.MethodHead, handlePath},
	} {
		code, h, body := do(c.method, c.path, auth)
		wantBody := "Method Not Allowed\n"
		if c.method == http.MethodHead {
			wantBody = ""
		}
		plain(c.method+" "+c.path, code, h, body, http.StatusMethodNotAllowed, wantBody)
	}
	for _, path := range []string{"/_escrow/not-a-handle", "/_escrow/kaaaaaaaaaa", "/_escrow/kaaaaaaaaaa/meta", handlePath + "/other", "/_escrow/"} {
		code, h, body := do(http.MethodGet, path, auth)
		plain("GET "+path, code, h, body, http.StatusNotFound, "Not Found\n")
	}

	code, h, body = do(http.MethodDelete, handlePath, auth)
	if code != http.StatusNoContent || len(body) != 0 || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("delete = %d %v %q", code, h, body)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, handlePath}, {http.MethodGet, metaPath}, {http.MethodDelete, handlePath},
	} {
		code, h, body := do(c.method, c.path, auth)
		plain(c.method+" "+c.path+" after delete", code, h, body, http.StatusNotFound, "Not Found\n")
	}
}

// jsonKeys returns the member names of a JSON object, in order.
func jsonKeys(t *testing.T, data []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not a JSON object: %q", data)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		k, _ := tok.(string)
		keys = append(keys, k)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
