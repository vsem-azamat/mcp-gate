package approval

import (
	"encoding/json"
	"net/http"

	"github.com/vsem-azamat/mcp-gate/internal/audit"
)

// Routes of the endpoints that decide.
const (
	// Route lists the pending approvals, and with /<id>/approve or /<id>/deny decides one.
	Route = "/_approvals"
	// LinkRoute, followed by a link token and /approve or /deny, decides through a link.
	LinkRoute = "/_approvals/link/"
)

// listBody is the answer of GET /_approvals.
type listBody struct {
	Pending []Pending `json:"pending"`
}

// decidedBody is the answer of a decision.
type decidedBody struct {
	ID       string         `json:"id"`
	Approval audit.Approval `json:"approval"`
}

// AdminHandler serves GET /_approvals and POST /_approvals/{id}/approve|deny to requests that
// admin authenticates, with the token's name as the approver; others get 401, and rejected, if
// set, is called for each.
func (st *Store) AdminHandler(admin func(header string) (string, bool), rejected func()) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Route, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, listBody{Pending: st.List()})
	})
	decide := func(approve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			by, _ := admin(r.Header.Get("Authorization"))
			id := r.PathValue("id")
			a, ok := st.Decide(id, approve, by)
			if !ok {
				http.Error(w, "no pending approval with this id", http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, decidedBody{ID: id, Approval: a})
		}
	}
	mux.HandleFunc("POST "+Route+"/{id}/approve", decide(true))
	mux.HandleFunc("POST "+Route+"/{id}/deny", decide(false))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := admin(r.Header.Get("Authorization")); !ok {
			if rejected != nil {
				rejected()
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// LinkHandler serves POST /_approvals/link/{token}/approve|deny without a token, the link token
// being the credential; any other method gets 405, so that fetching a link decides nothing.
func (st *Store) LinkHandler() http.Handler {
	mux := http.NewServeMux()
	decide := func(approve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id, a, ok := st.DecideLink(r.PathValue("token"), approve)
			if !ok {
				http.Error(w, "no pending approval for this link", http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, decidedBody{ID: id, Approval: a})
		}
	}
	mux.HandleFunc("POST "+LinkRoute+"{token}/approve", decide(true))
	mux.HandleFunc("POST "+LinkRoute+"{token}/deny", decide(false))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "cannot encode the answer", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(append(body, '\n'))
}
