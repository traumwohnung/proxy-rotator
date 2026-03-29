package core

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// SOCKS5Upstream implements Upstream using the SOCKS5 protocol.
// Uses golang.org/x/net/proxy which is the standard Go SOCKS5 client,
// handling RFC 1928 + RFC 1929 auth correctly.
type SOCKS5Upstream struct{}

func (SOCKS5Upstream) Dial(ctx context.Context, p *Proxy, target string) (net.Conn, error) {
	addr := hostPort(p.Host, p.Port)

	var auth *proxy.Auth
	if p.Username != "" {
		auth = &proxy.Auth{User: p.Username, Password: p.Password}
	}

	dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("creating SOCKS5 dialer for %s: %w", addr, err)
	}

	// Use DialContext if available for proper cancellation support.
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", target)
	}
	return dialer.Dial("tcp", target)
}
