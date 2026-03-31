package proxykit

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

type SOCKS5Upstream struct {
	// DialTimeout overrides DefaultUpstreamDialTimeout.
	// Zero means use the default.
	DialTimeout time.Duration
}

func (u SOCKS5Upstream) dialTimeout() time.Duration {
	if u.DialTimeout != 0 {
		return u.DialTimeout
	}
	return DefaultUpstreamDialTimeout
}

func (u SOCKS5Upstream) Dial(ctx context.Context, p *Proxy, target string) (net.Conn, error) {
	addr := hostPort(p.Host, p.Port)

	var auth *proxy.Auth
	if p.Username != "" {
		auth = &proxy.Auth{User: p.Username, Password: p.Password}
	}

	baseDialer := &net.Dialer{Timeout: u.dialTimeout()}
	dialer, err := proxy.SOCKS5("tcp", addr, auth, baseDialer)
	if err != nil {
		return nil, fmt.Errorf("creating SOCKS5 dialer for %s: %w", addr, err)
	}

	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", target)
	}
	return dialer.Dial("tcp", target)
}
