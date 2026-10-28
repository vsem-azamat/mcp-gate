package approval

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/vsem-azamat/mcp-gate/internal/oauth"
)

// WebhookTimeout bounds one notice.
const WebhookTimeout = 10 * time.Second

// SignatureHeader carries the HMAC-SHA256 of a notice's body, as "sha256=<hex>".
const SignatureHeader = "X-Mcp-Gate-Signature"

// Notice is what a notifier announces of a pending approval: the pending approval and, with
// links, the URLs that decide it once.
type Notice struct {
	Pending
	ApproveURL string `json:"approveURL,omitempty"`
	DenyURL    string `json:"denyURL,omitempty"`
}

// Notifier announces pending approvals. Notify runs on a goroutine of its own and must return.
type Notifier interface {
	Notify(Notice)
}

// Webhook posts each notice as JSON to a URL.
type Webhook struct {
	url    string
	secret []byte
	client *http.Client
	logger *slog.Logger
}

// NewWebhook returns the notifier that posts to rawURL, signing the body with secret when it is
// not empty. It follows no redirect and connects to no link-local or cloud metadata address.
func NewWebhook(rawURL, secret string, logger *slog.Logger) *Webhook {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	d := &net.Dialer{Timeout: WebhookTimeout, Control: refuseMetadata}
	t := &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: WebhookTimeout, DisableKeepAlives: true, ForceAttemptHTTP2: true}
	w := &Webhook{url: rawURL, logger: logger, client: &http.Client{
		Transport: t, Timeout: WebhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	if secret != "" {
		w.secret = []byte(secret)
	}
	return w
}

// refuseMetadata refuses a connection to an address no request of the gate may reach.
func refuseMetadata(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	a, err := netip.ParseAddr(host)
	if err != nil || oauth.AlwaysRefused(a) {
		return errors.New("refused to connect to a link-local or metadata address")
	}
	return nil
}

// Sign returns the signature header value of body under secret.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Notify posts n, and logs a warning when that fails; the URL is never logged.
func (w *Webhook) Notify(n Notice) {
	if err := w.post(n); err != nil {
		w.logger.Warn("approval webhook failed; the call still waits for a decision", "server", n.Server, "tool", n.Tool, "id", n.ID, "error", err.Error())
	}
}

func (w *Webhook) post(n Notice) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), WebhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	if w.secret != nil {
		req.Header.Set(SignatureHeader, Sign(w.secret, body))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // without the URL
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("answered %d", resp.StatusCode)
	}
	return nil
}
