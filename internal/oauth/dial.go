package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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

// alwaysRefused reports addresses that are refused even for a local server: link-local ones
// and others where cloud metadata services answer, and IPv6 forms that embed an IPv4 address
// (NAT64, 6to4, Teredo), which could reach one.
func alwaysRefused(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range metadataPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS, IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
	netip.MustParsePrefix("192.0.0.192/32"),     // Oracle Cloud
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

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
	local  bool // the configured server is local; decided once
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
	switch {
	case aerr == nil:
		if g.refused(a) {
			return nil, fmt.Errorf("%w %s", errNonPublic, host)
		}
	case numericHost(host) || (isLocalName(host) && !g.local):
		return nil, fmt.Errorf("%w %s", errNonPublic, host)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[u.Scheme]
	}
	g.mu.Lock()
	g.proxies[net.JoinHostPort(u.Hostname(), port)] = true
	g.mu.Unlock()
	return u, nil
}

// guardedTransport returns a transport for requests on behalf of the server at serverURL, which
// picks proxies with proxy.
func guardedTransport(serverURL string, proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	var host string
	if u, err := url.Parse(serverURL); err == nil {
		host = u.Hostname()
	}
	g := &guard{
		local: localHost(host), proxy: proxy, proxies: map[string]bool{},
		dialer: &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
	}
	t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's default transport
	t.DisableKeepAlives = true
	t.DialContext = g.dialContext
	t.Proxy = g.proxyFor
	return t
}
