package oauth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The SDK sends discovery requests through a clone of the discovery transport, which offers h2
// in TLS; the transport must then speak it, or servers that pick h2 answer in frames the
// HTTP/1 reader cannot parse.
func TestDiscoveryClientSpeaksHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr := discoveryClient(&http.Client{Timeout: 5 * time.Second}).Transport.(*http.Transport).Clone()                                         //nolint:forcetypeassert // built above
	tr.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12} //nolint:forcetypeassert // httptest's client
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Proto"); got != "HTTP/2.0" {
		t.Errorf("served over %s, want HTTP/2.0", got)
	}
}
