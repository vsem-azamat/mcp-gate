package oauth

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestNonPublic(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.8.9.10", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"fe80::1", true},
		{"fd00:ec2::254", true},
		{"100.64.0.1", true},
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"::", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"255.255.255.255", true},
		{"240.0.0.1", true},
		{"198.18.0.1", true},
		{"64:ff9b::a9fe:a9fe", true},
		{"2002:7f00:1::", true},
		{"::127.0.0.1", true},
		{"93.184.215.14", false},
		{"8.8.8.8", false},
		{"203.0.113.7", false},
		{"2606:4700::1111", false},
		{"::ffff:8.8.8.8", false},
	} {
		if got := nonPublic(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("nonPublic(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func noProxy(*http.Request) (*url.URL, error) { return nil, nil } //nolint:nilnil // no proxy is no error

func get(t *testing.T, tr *http.Transport, target string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func TestGuardRefusesNonPublicEndpoints(t *testing.T) {
	t.Parallel()
	endpoint := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(endpoint.Close)
	byName := strings.Replace(endpoint.URL, "127.0.0.1", "localhost", 1)

	for _, tc := range []struct {
		name, server, target string
		refused              bool
	}{
		{"public server, loopback endpoint", "https://mcp.example.com/mcp", endpoint.URL, true},
		// The name is resolved when it is dialed, so a name that resolves to loopback is
		// refused too.
		{"public server, endpoint name resolving to loopback", "https://mcp.example.com/mcp", byName, true},
		// Only how the server is written counts, never what its name resolves to, which its
		// operator controls.
		{"server name that resolves to loopback", "http://localtest.example/mcp", endpoint.URL, true},
		{"server on loopback", "http://127.0.0.1:9/mcp", endpoint.URL, false},
		{"server on a LAN address", "http://192.168.1.20/mcp", endpoint.URL, false},
		{"server named localhost", "http://localhost:9/mcp", byName, false},
		{"local server, metadata endpoint", "http://127.0.0.1:9/mcp", "http://169.254.169.254:1/token", true},
		{"local server, IPv6 link-local endpoint", "http://127.0.0.1:9/mcp", "http://[fe80::1%25lo]:1/token", true},
		{"local server, IPv6 metadata endpoint", "http://127.0.0.1:9/mcp", "http://[fd00:ec2::254]:1/token", true},
		{"local server, NAT64 of a metadata endpoint", "http://127.0.0.1:9/mcp", "http://[64:ff9b::a9fe:a9fe]:1/token", true},
		{"local server, other metadata endpoint", "http://127.0.0.1:9/mcp", "http://100.100.100.200:1/token", true},
		{"local server, IPv4-compatible metadata endpoint", "http://127.0.0.1:9/mcp", "http://[::a9fe:a9fe]:1/token", true},
		{"local server, IPv4-translated metadata endpoint", "http://127.0.0.1:9/mcp", "http://[::ffff:0:a9fe:a9fe]:1/token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := get(t, guardedTransport(tc.server, noProxy), tc.target)
			if tc.refused != errors.Is(err, errNonPublic) || (!tc.refused && err != nil) {
				t.Errorf("err = %v, refused = %v", err, tc.refused)
			}
		})
	}
}

func TestGuardBehindProxy(t *testing.T) {
	t.Parallel()
	var (
		mu   sync.Mutex
		seen []string
	)
	proxySrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.URL.String())
	}))
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	viaProxy := func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	tr := guardedTransport("https://mcp.example.com/mcp", viaProxy)
	// The proxy is on loopback and is allowed; the target is the proxy's to resolve.
	if err := get(t, tr, "http://auth.example.com/token"); err != nil {
		t.Errorf("a public name through a loopback proxy: %v", err)
	}
	for _, target := range []string{
		"http://169.254.169.254/latest", "http://localhost:8080/token", "http://[::1]/token",
		"http://metadata/computeMetadata", "http://metadata.google.internal/computeMetadata",
		"http://nas.lan/token", "http://printer.local/token", "http://router.home.arpa/token",
		"http://127.0.0.1./token", "http://127.1/token", "http://2130706433/token",
		"http://0x7f000001/token", "http://017700000001/token", "http://localhost./token",
	} {
		if err := get(t, tr, target); !errors.Is(err, errNonPublic) {
			t.Errorf("%s through the proxy: err = %v, want a refusal", target, err)
		}
	}
	mu.Lock()
	if len(seen) != 1 {
		t.Errorf("the proxy saw %v, want only the public target", seen)
	}
	mu.Unlock()
	local := guardedTransport("http://127.0.0.1:9/mcp", viaProxy)
	if err := get(t, local, "http://localhost:8080/token"); err != nil {
		t.Errorf("a local target of a local server through the proxy: %v", err)
	}
	if err := get(t, local, "http://nas.lan/token"); err != nil {
		t.Errorf("an internal name for a local server through the proxy: %v", err)
	}
	if err := get(t, local, "http://169.254.169.254/latest"); !errors.Is(err, errNonPublic) {
		t.Errorf("a metadata target of a local server through the proxy: err = %v", err)
	}
}

func TestAlwaysRefused(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"169.254.169.254": true, "::a9fe:a9fe": true, "::ffff:0:a9fe:a9fe": true, "fe80::1": true,
		"::1": false, "127.0.0.1": false, "10.0.0.1": false, "192.168.1.1": false, "::ffff:127.0.0.1": false,
	} {
		if got := alwaysRefused(netip.MustParseAddr(addr)); got != want {
			t.Errorf("alwaysRefused(%s) = %v, want %v", addr, got, want)
		}
	}
}

// The configured server's own host:port is reached whatever it resolves to (its MCP traffic
// goes there anyway), so a server on a LAN or tailnet name can answer the challenge; metadata
// addresses stay refused, and other ports of the same host are guarded.
func TestGuardExemptsTheServerItself(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(other.Close)
	u, _ := url.Parse(srv.URL)
	g := &guard{server: hostPort(u), proxy: noProxy, proxies: map[string]bool{}, dialer: &net.Dialer{}} // as for a name that resolves privately
	tr := g.transport()
	if err := get(t, tr, srv.URL+"/mcp"); err != nil {
		t.Errorf("the server itself: %v", err)
	}
	if err := get(t, tr, other.URL+"/token"); !errors.Is(err, errNonPublic) {
		t.Errorf("another port on the same address: err = %v, want a refusal", err)
	}
	g.server = "169.254.169.254:80"
	if err := get(t, g.transport(), "http://169.254.169.254/latest"); !errors.Is(err, errNonPublic) {
		t.Errorf("a server on a metadata address: err = %v, want a refusal", err)
	}
}
