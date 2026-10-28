package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// errNonPublic is the cause of a request refused for its address.
var errNonPublic = errors.New("refused to connect to a non-public address")

// reservedPrefixes are ranges that are not reachable on the internet beyond those netip
// classifies (loopback, private, link-local, multicast, unspecified).
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and the broadcast address
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64, which can reach any IPv4 address
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local NAT64
	netip.MustParsePrefix("100::/64"),        // discard
	netip.MustParsePrefix("2002::/16"),       // 6to4, which embeds an IPv4 address
	netip.MustParsePrefix("fec0::/10"),       // site-local
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("::/96"),           // IPv4-compatible
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
}

// nonPublic reports whether a is an address that a remote document must not point the gate
// at: loopback, private, link-local (cloud metadata), multicast, unspecified or reserved.
func nonPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// isLocalName reports whether host is a name that always resolves to the machine itself.
func isLocalName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// alwaysRefused reports addresses that are refused even for a local server and for the
// server's own host: link-local ones and others where cloud metadata services answer, and IPv6
// forms that embed an IPv4 address (IPv4-compatible, IPv4-translated, NAT64, 6to4, Teredo),
// which could reach one.
func alwaysRefused(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() {
		return false // ::1 lies in ::/96
	}
	if a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range alwaysRefusedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// AlwaysRefused reports an address that no outgoing request of the gate may reach, whoever
// configured it (see alwaysRefused).
func AlwaysRefused(a netip.Addr) bool { return alwaysRefused(a) }

var alwaysRefusedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS metadata, IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("192.0.0.192/32"),     // Oracle Cloud metadata
	netip.MustParsePrefix("::/96"),              // IPv4-compatible; ::1, loopback, is let through above
	netip.MustParsePrefix("::ffff:0:0:0/96"),    // IPv4-translated
	netip.MustParsePrefix("64:ff9b::/96"),       // NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),     // local NAT64
	netip.MustParsePrefix("2002::/16"),          // 6to4
	netip.MustParsePrefix("2001::/32"),          // Teredo
}

// internalSuffixes are name suffixes of private networks, refused behind a proxy for a server
// that is not local, as are single-label names.
var internalSuffixes = []string{".internal", ".local", ".lan", ".home.arpa", ".localdomain", ".intranet", ".corp"}

// internalName reports a name that only resolves inside a private network: a single label
// ("metadata") or one under a private suffix ("metadata.google.internal", "nas.lan").
func internalName(host string) bool {
	host = strings.ToLower(host)
	if !strings.Contains(host, ".") {
		return true
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

// metadataNames are names of cloud metadata services, refused behind a proxy in every case.
var metadataNames = []string{"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}

// metadataName reports a name of a cloud metadata service.
func metadataName(host string) bool {
	return slices.Contains(metadataNames, strings.ToLower(host))
}

// defaultPorts are the ports of server and proxy URLs that name none.
var defaultPorts = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}

// localHost reports whether a configured server host is written as a non-public address or a
// local name. A name that merely resolves to such an address does not count: whoever runs the
// server's DNS could otherwise switch the guard off.
func localHost(host string) bool {
	if isLocalName(host) {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && nonPublic(a)
}

// numericHost reports a host that is no address netip parses but that resolvers or proxies may
// read as one: "127.1", "2130706433", "0x7f000001", "017700000001". A DNS name never has a
// numeric last label.
func numericHost(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if strings.HasPrefix(strings.ToLower(last), "0x") {
		return true
	}
	return last != "" && strings.Trim(last, "0123456789") == ""
}

// guard refuses connections to non-public addresses for requests whose URLs come from remote
// metadata (the token and registration endpoints), unless the configured server is written as
// such an address or a local name: then its authorization server may be local too. Link-local
// addresses are refused either way.
type guard struct {
	local bool // the configured server is local; decided once
	// server is the configured server's host:port, lower-case. Its own traffic goes there
	// unguarded anyway (the MCP connection), so requests to it are checked only against
	// alwaysRefused, which lets a server on a LAN or tailnet name answer the challenge.
	server string
	dialer *net.Dialer
	proxy  func(*http.Request) (*url.URL, error)

	mu      sync.Mutex
	proxies map[string]bool // host:port of the proxies requests were sent through
}

// refused reports whether a connection to a is refused.
func (g *guard) refused(a netip.Addr) bool {
	return alwaysRefused(a) || (!g.local && nonPublic(a))
}

// control runs on every connection the dialer opens, after the name was resolved, so that a
// name that resolves to a public address when checked and to a private one when dialed (DNS
// rebinding) is refused too.
func (g *guard) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	a, err := netip.ParseAddr(host)
	if err != nil || g.refused(a) {
		return fmt.Errorf("%w %s", errNonPublic, host)
	}
	return nil
}

// controlServer checks a connection to the configured server's own host:port.
func (g *guard) controlServer(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	a, err := netip.ParseAddr(host)
	if err != nil || alwaysRefused(a) {
		return fmt.Errorf("%w %s", errNonPublic, host)
	}
	return nil
}

// dialContext dials address, checking the address dialed unless it is a proxy that a request
// goes through, which the environment configures.
func (g *guard) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	g.mu.Lock()
	viaProxy := g.proxies[address]
	g.mu.Unlock()
	if viaProxy {
		return g.dialer.DialContext(ctx, network, address)
	}
	d := *g.dialer
	d.Control = g.control
	if strings.EqualFold(address, g.server) {
		d.Control = g.controlServer
	}
	return d.DialContext(ctx, network, address)
}

// proxyFor picks the proxy of a request from the environment. Behind a proxy the gate does not
// resolve the target, so only a target written as an address, in a numeric form a resolver
// may read as one, or as a local name is checked; other names are the proxy's to resolve. The
// proxy's own address is allowed.
func (g *guard) proxyFor(req *http.Request) (*url.URL, error) {
	u, err := g.proxy(req)
	if err != nil || u == nil {
		return u, err
	}
	host := strings.TrimSuffix(req.URL.Hostname(), ".")
	a, aerr := netip.ParseAddr(host)
	ownServer := strings.EqualFold(hostPort(req.URL), g.server)
	switch {
	case aerr == nil:
		if alwaysRefused(a) || (!ownServer && g.refused(a)) {
			return nil, fmt.Errorf("%w %s", errNonPublic, host)
		}
	case numericHost(host) || metadataName(host):
		return nil, fmt.Errorf("%w %s", errNonPublic, host)
	case !ownServer && !g.local && (isLocalName(host) || internalName(host)):
		return nil, fmt.Errorf("%w %s", errNonPublic, host)
	}
	port := u.Port()
	if port == "" {
		port = defaultPorts[u.Scheme]
	}
	g.mu.Lock()
	g.proxies[net.JoinHostPort(u.Hostname(), port)] = true
	g.mu.Unlock()
	return u, nil
}

// hostPort returns the host:port a URL is dialed at.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = defaultPorts[u.Scheme]
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// guardedTransport returns a transport for requests on behalf of the server at serverURL, which
// picks proxies with proxy.
func guardedTransport(serverURL string, proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	var host, server string
	if u, err := url.Parse(serverURL); err == nil {
		host, server = u.Hostname(), strings.ToLower(hostPort(u))
	}
	return (&guard{
		local: localHost(host), server: server, proxy: proxy, proxies: map[string]bool{},
		dialer: &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
	}).transport()
}

// transport returns a transport that dials and picks proxies through g.
func (g *guard) transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's default transport
	t.DisableKeepAlives = true
	t.DialContext = g.dialContext
	t.Proxy = g.proxyFor
	return t
}
